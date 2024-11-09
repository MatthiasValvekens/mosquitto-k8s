package main

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"mosquitto-go-auth-k8s/topics"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var version = "v0.0.1"

type K8sAuthConfig struct {
	Namespace string
	Audiences []string
}
type Session struct {
	userName               string
	readableTopicPatterns  []string
	writableTopicPatterns  []string
	sessionStart           time.Time
	lastUpdate             time.Time
	lastUsed               time.Time
	authenticatedWithToken bool
}

var authConfig K8sAuthConfig
var clientset *kubernetes.Clientset

// Cache on client id (only one session per client ID per MQTT spec)
// a reconnection always triggers a reauthentication, so even if the client ID
// remains the same, the authentication state is always refreshed when a client reconnects.
// Caching on username would not invalidate the cache on a reconnect, which probably
// creates more problems than it solves. It would also require us to either rethink the way
// we distinguish between legacy username/password auth vs token-based (currently done using the __token__ username),
// or reset the client's username to the canonical one in mosquitto after authenticating, which is also a bit messy.
var clientSessionCache map[string]Session
var cacheDuration time.Duration
var sessionTimeout time.Duration

func isTopicInList(topicList []string, searchedTopic string, username string, clientid string) bool {
	replacer := strings.NewReplacer("%u", username, "%c", clientid)

	for _, topicFromList := range topicList {
		if topics.Match(replacer.Replace(topicFromList), searchedTopic) {
			return true
		}
	}
	return false
}

func checkAccessToTopic(topic string, acc int32, cache *Session, username string, clientid string) bool {
	log.Debugf("Check for acl level %d", acc)

	// check read access
	if acc == 1 || acc == 4 {
		res := isTopicInList(cache.readableTopicPatterns, topic, username, clientid)
		log.Debugf("ACL for read was %t", res)
		return res
	}

	// check write
	if acc == 2 {
		res := isTopicInList(cache.writableTopicPatterns, topic, username, clientid)
		log.Debugf("ACL for write was %t", res)
		return res
	}

	// check for readwrite
	if acc == 3 {
		res := isTopicInList(cache.readableTopicPatterns, topic, username, clientid) && isTopicInList(cache.writableTopicPatterns, topic, username, clientid)
		log.Debugf("ACL for readwrite was %t", res)
		return res
	}
	return false
}

func cacheIsValid(now time.Time, cache *Session) bool {
	return now.Sub(cache.lastUpdate) < cacheDuration
}

func sessionIsAlive(now time.Time, cache *Session) bool {
	return now.Sub(cache.lastUsed) < sessionTimeout
}

func startSessionWithUsernamePassword(username string, password string) *Session {
	// legacy IoT clients with a password that is passed around in the clear

	userInfo, err := getAccountMetadata(username)
	if err != nil {
		return nil
	}

	if userInfo.DirectPassword == "" {
		log.Warnf("Password login is disabled for user %s", username)
		return nil
	}

	if userInfo.DirectPassword != password {
		return nil
	}

	now := time.Now()
	return &Session{
		userName:               username,
		sessionStart:           now,
		lastUpdate:             now,
		lastUsed:               now,
		readableTopicPatterns:  userInfo.TopicAccess.ReadPatterns,
		writableTopicPatterns:  userInfo.TopicAccess.WritePatterns,
		authenticatedWithToken: false,
	}
}

func startSessionWithToken(accessToken string) *Session {

	info := authenticateServiceAccount(accessToken)

	if info == nil {
		return nil
	}

	now := time.Now()
	return &Session{
		userName:               info.Username,
		sessionStart:           now,
		lastUpdate:             now,
		lastUsed:               now,
		readableTopicPatterns:  info.TopicAccess.ReadPatterns,
		writableTopicPatterns:  info.TopicAccess.WritePatterns,
		authenticatedWithToken: true,
	}
}

func InitBackend(authOpts map[string]string, logLevel log.Level) error {
	log.SetLevel(logLevel)

	config, err := rest.InClusterConfig()

	if err != nil {
		log.Panic("This plugin only works in a k8s pod")
	}

	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Panic("Failed to initialise k8s clientset")
	}

	log.Infof("k8s Plugin " + version + " initialized!")
	namespace, ok := authOpts["k8s_namespace"]
	if !ok {
		namespaceBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		namespace = string(namespaceBytes)
		if err != nil {
			log.Panic("No k8s_namespace specified, failed to read it from the pod")
		}
	}
	audiences, ok := authOpts["k8s_audiences"]
	var audienceSplit []string
	if ok {
		audienceSplit = strings.Split(strings.Replace(audiences, " ", "", -1), ",")
	} else {
		audienceSplit = []string{"mosquitto"}
	}
	cacheDurationSeconds, ok := authOpts["k8s_cache_duration"]
	if ok {
		durationInt, err := strconv.Atoi(cacheDurationSeconds)
		if err != nil {
			log.Panic("Got no valid cache duration for k8s plugin.")
		}

		cacheDuration = time.Duration(durationInt) * time.Second
	} else {
		cacheDuration = 5 * time.Minute
	}

	sessionTimeoutSeconds, ok := authOpts["k8s_session_timeout"]
	if ok {
		durationInt, err := strconv.Atoi(sessionTimeoutSeconds)
		if err != nil {
			log.Panic("Got no valid session timeout for k8s plugin.")
		}

		sessionTimeout = time.Duration(durationInt) * time.Second
	} else {
		// this setting is mostly a memory management thing, it doesn't make sense
		// if it's not significantly longer than the cache duration time.
		sessionTimeout = max(2*cacheDuration, 10*time.Minute)
	}

	authConfig = K8sAuthConfig{
		Namespace: namespace,
		Audiences: audienceSplit,
	}

	clientSessionCache = make(map[string]Session)

	return nil
}

func GetUser(username string, password string, clientid string) bool {
	// Get token for the credentials and verify the user
	log.Infof("Checking user with k8s plugin.")
	var user *Session
	if username == "__token__" {
		user = startSessionWithToken(password)
	} else {
		user = startSessionWithUsernamePassword(username, password)
	}

	if user != nil {
		clientSessionCache[clientid] = *user
		return true
	}
	return false
}

func cleanOldCacheEntries() {
	var toDelete []string
	now := time.Now()
	for clientId, session := range clientSessionCache {
		if !sessionIsAlive(now, &session) {
			toDelete = append(toDelete, clientId)
		}
	}
	for _, clientId := range toDelete {
		delete(clientSessionCache, clientId)
	}
}

func refreshUserCacheIfStale(username string, clientId string) *Session {
	cleanOldCacheEntries()

	cache, ok := clientSessionCache[clientId]
	if !ok {
		log.Warnf("Have no entry in user cache for user %s", username)
		return nil
	}

	now := time.Now()
	if !cacheIsValid(now, &cache) {
		info, err := getAccountMetadata(cache.userName)

		if err != nil {
			log.Errorf("Failed to receive ServiceAccountMetadata for user %s: %s", cache.userName, err)
			return nil
		}

		cache.readableTopicPatterns = info.TopicAccess.ReadPatterns
		cache.writableTopicPatterns = info.TopicAccess.WritePatterns
		cache.lastUpdate = now
		log.Debug("Refreshed access info in cache")
	} else {
		log.Debug("Get access from cache")
	}
	cache.lastUsed = now
	return &cache
}

func CheckAcl(username, topic, clientid string, acc int32) bool {
	// Function that checks if the user has the right to access a topic
	log.Debugf("Checking if user %s is allowed to access topic %s with access %d.", username, topic, acc)

	cache := refreshUserCacheIfStale(username, clientid)
	if cache == nil {
		return false
	}

	res := checkAccessToTopic(topic, acc, cache, username, clientid)
	log.Debugf("ACL check was %t", res)
	return res
}
