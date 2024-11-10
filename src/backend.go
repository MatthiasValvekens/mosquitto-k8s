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
type CachedUserData struct {
	userName              string
	readableTopicPatterns []string
	writableTopicPatterns []string
	lastUpdate            time.Time
	lastUsed              time.Time
}

var authConfig K8sAuthConfig
var clientset *kubernetes.Clientset

var userDataCache map[string]CachedUserData
var cacheValidity time.Duration
var cacheTimeout time.Duration

func isTopicInList(topicList []string, searchedTopic string, username string, clientid string) bool {
	log.Debugf("Checking if topic %s is in list %s", searchedTopic, strings.Join(topicList, ","))
	replacer := strings.NewReplacer("%u", username, "%c", clientid)

	for _, topicFromList := range topicList {
		if topics.Match(replacer.Replace(topicFromList), searchedTopic) {
			return true
		}
	}
	return false
}

func checkAccessToTopic(topic string, acc int32, cached *CachedUserData, clientid string) bool {
	log.Debugf("Check for acl level %d", acc)

	// check read access
	if acc == 1 || acc == 4 {
		res := isTopicInList(cached.readableTopicPatterns, topic, cached.userName, clientid)
		log.Debugf("ACL for read was %t", res)
		return res
	}

	// check write
	if acc == 2 {
		res := isTopicInList(cached.writableTopicPatterns, topic, cached.userName, clientid)
		log.Debugf("ACL for write was %t", res)
		return res
	}

	// check for readwrite
	if acc == 3 {
		res := isTopicInList(cached.readableTopicPatterns, topic, cached.userName, clientid) && isTopicInList(cached.writableTopicPatterns, topic, cached.userName, clientid)
		log.Debugf("ACL for readwrite was %t", res)
		return res
	}
	return false
}

func cacheIsValid(now time.Time, cache *CachedUserData) bool {
	return now.Sub(cache.lastUpdate) < cacheValidity
}

func cacheIsUnused(now time.Time, cache *CachedUserData) bool {
	return now.Sub(cache.lastUsed) < cacheTimeout
}

func initCacheEntry(info ServiceAccountMetadata, now time.Time) *CachedUserData {
	return &CachedUserData{
		userName:              info.UserName,
		lastUpdate:            now,
		lastUsed:              now,
		readableTopicPatterns: info.TopicAccess.ReadPatterns,
		writableTopicPatterns: info.TopicAccess.WritePatterns,
	}
}

func startSessionWithUsernamePassword(username string, password string) *CachedUserData {
	// legacy IoT clients with a password that is passed around in the clear

	userInfo, err := getAccountMetadata(username)
	if err != nil || userInfo == nil {
		return nil
	}

	if userInfo.DirectPassword == "" {
		log.Warnf("Password login is disabled for user %s", username)
		return nil
	}

	if userInfo.DirectPassword != password {
		return nil
	}

	return initCacheEntry(*userInfo, time.Now())
}

func startSessionWithToken(accessToken string) *CachedUserData {

	info := authenticateServiceAccount(accessToken)

	if info == nil {
		return nil
	}

	return initCacheEntry(*info, time.Now())
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

		cacheValidity = time.Duration(durationInt) * time.Second
	} else {
		log.Panic("No k8s_cache_duration specified")
	}

	sessionTimeoutSeconds, ok := authOpts["k8s_pruning_interval"]
	if ok {
		durationInt, err := strconv.Atoi(sessionTimeoutSeconds)
		if err != nil {
			log.Panic("Got no valid session timeout for k8s plugin.")
		}

		cacheTimeout = time.Duration(durationInt) * time.Second
	} else {
		log.Panic("No k8s_pruning_interval specified")
	}

	authConfig = K8sAuthConfig{
		Namespace: namespace,
		Audiences: audienceSplit,
	}

	userDataCache = make(map[string]CachedUserData)

	return nil
}

func GetUser(username string, password string) *string {
	// Get token for the credentials and verify the user
	log.Infof("Checking user with k8s plugin.")
	var user *CachedUserData

	// we always refresh the cache on a new connection
	if username == "__token__" {
		user = startSessionWithToken(password)
	} else {
		user = startSessionWithUsernamePassword(username, password)
	}

	if user != nil {
		userDataCache[user.userName] = *user
		return &user.userName
	}
	return nil
}

func cleanOldCacheEntries(now time.Time) {
	var deletionCandidates []string
	for user, userData := range userDataCache {
		if !cacheIsUnused(now, &userData) {
			deletionCandidates = append(deletionCandidates, user)
		}
	}
	for _, user := range deletionCandidates {
		log.Infof("Pruning cache for user %s", user)
		delete(userDataCache, user)
	}
}

func refreshUserCacheIfStale(username string) *CachedUserData {
	now := time.Now()
	cache, ok := userDataCache[username]
	if !ok {
		log.Infof("Have no entry in user cache for user %s, recreating...", username)
		userDataCache[username] = CachedUserData{}
	}

	if !ok || !cacheIsValid(now, &cache) {
		info, err := getAccountMetadata(cache.userName)

		if err != nil {
			log.Errorf("Failed to receive ServiceAccountMetadata for user %s: %s", cache.userName, err)
			delete(userDataCache, username)
			return nil
		}

		cache.readableTopicPatterns = info.TopicAccess.ReadPatterns
		cache.writableTopicPatterns = info.TopicAccess.WritePatterns
		cache.lastUpdate = now
		log.Debugf("Refreshed access info in cache for user %s", username)
	} else {
		log.Debugf("Get access from cache for user %s", username)
	}
	cache.lastUsed = now

	// clean up other old cache entries
	cleanOldCacheEntries(now)
	return &cache
}

func CheckAcl(username, topic, clientid string, acc int32) bool {
	// Function that checks if the user has the right to access a topic
	log.Debugf("Checking if user %s is allowed to access topic %s with access %d.", username, topic, acc)

	cache := refreshUserCacheIfStale(username)
	if cache == nil {
		return false
	}

	res := checkAccessToTopic(topic, acc, cache, clientid)
	log.Debugf("ACL check was %t", res)
	return res
}
