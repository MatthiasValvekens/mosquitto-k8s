package main

import (
	"context"
	v1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"mosquitto-go-auth-k8s/topics"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type K8sAuthConfig struct {
	Namespace string
	Audiences []string
}
type authenticatedUser struct {
	username           string
	readTopics         []string
	writeTopics        []string
	lastUserInfoUpdate time.Time
	createdAt          time.Time
	updatedAt          time.Time
	withToken          bool
}

type UserInfo struct {
	Topics struct {
		Read  []string `json:"read"`
		Write []string `json:"write"`
	} `json:"topics"`
	DirectPassword string `json:"directPassword"` // for non-k8s clients
}

var serviceAccountRegex = regexp.MustCompile(`system:serviceaccount:(?P<Namespace>[-_a-zA-Z0-9]+):(?P<AccountName>[-_a-zA-Z0-9]+)`)

var authConfig K8sAuthConfig
var clientset *kubernetes.Clientset

// cache on client id (expected to be unique)
var userCache map[string]authenticatedUser
var cacheDuration time.Duration
var version string

func getUserInfo(accountName string) (*UserInfo, error) {
	info := UserInfo{}

	ctx := context.TODO()

	account, err := clientset.CoreV1().ServiceAccounts(authConfig.Namespace).Get(ctx, accountName, metav1.GetOptions{})

	if err != nil {
		log.Warnf("Error fetching account %s: %s", account, err.Error())
		return nil, err
	}

	annots := account.Annotations
	passwordSecretRef, ok := annots["mqtt.dev.mvalvekens.be/password-secret"]

	info.DirectPassword = ""
	if ok {
		log.Debugf("User %s has password login enabled, reading from secret %s", accountName, passwordSecretRef)
		secret, err := clientset.CoreV1().Secrets(authConfig.Namespace).Get(ctx, passwordSecretRef, metav1.GetOptions{})
		if err == nil {
			passwordBytes, ok := secret.Data["MQTT_PASSWORD"]
			if ok {
				info.DirectPassword = string(passwordBytes)
			}
		}
	}

	readTopics, ok := annots["mqtt.dev.mvalvekens.be/allow-read"]
	if ok {
		log.Debugf("User %s has read access to %s", accountName, readTopics)
		info.Topics.Read = strings.Split(strings.Replace(readTopics, " ", "", -1), ",")
	} else {
		log.Debugf("User %s does not have read access to any topics", accountName)
		info.Topics.Read = []string{}
	}
	writeTopics, ok := annots["mqtt.dev.mvalvekens.be/allow-write"]
	if ok {
		log.Debugf("User %s has write access to %s", accountName, writeTopics)
		info.Topics.Write = strings.Split(strings.Replace(writeTopics, " ", "", -1), ",")
	} else {
		log.Debugf("User %s does not have write access to any topics", accountName)
		info.Topics.Write = []string{}
	}

	//infoJson, _ := json.Marshal(info)
	//log.Debugf("UserInfo %s", string(infoJson))
	return &info, nil
}

func isTopicInList(topicList []string, searchedTopic string, username string, clientid string) bool {
	replacer := strings.NewReplacer("%u", username, "%c", clientid)

	for _, topicFromList := range topicList {
		if topics.Match(replacer.Replace(topicFromList), searchedTopic) {
			return true
		}
	}
	return false
}

func checkAccessToTopic(topic string, acc int32, cache *authenticatedUser, username string, clientid string) bool {
	log.Debugf("Check for acl level %d", acc)

	// check read access
	if acc == 1 || acc == 4 {
		res := isTopicInList(cache.readTopics, topic, username, clientid)
		log.Debugf("ACL for read was %t", res)
		return res
	}

	// check write
	if acc == 2 {
		res := isTopicInList(cache.writeTopics, topic, username, clientid)
		log.Debugf("ACL for write was %t", res)
		return res
	}

	// check for readwrite
	if acc == 3 {
		res := isTopicInList(cache.readTopics, topic, username, clientid) && isTopicInList(cache.writeTopics, topic, username, clientid)
		log.Debugf("ACL for readwrite was %t", res)
		return res
	}
	return false
}

func cacheIsValid(cache *authenticatedUser) bool {
	log.Debugf("Cache Expiry: %s", cacheDuration)
	log.Debugf("Last Update: %s", cache.updatedAt)
	log.Debugf("Difference to now: %s", time.Now().Sub(cache.updatedAt))

	// function tests if the cache of the user is still valid
	if cacheDuration == 0 {
		return false
	}

	if (time.Now().Sub(cache.updatedAt)) < cacheDuration {
		return true
	}
	return false
}

func createUserWithPassword(username, password string) *authenticatedUser {
	// legacy IoT clients with a password that is passed around in the clear

	userInfo, err := getUserInfo(username)
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

	return &authenticatedUser{
		username:    username,
		createdAt:   time.Now(),
		updatedAt:   time.Now(),
		readTopics:  userInfo.Topics.Read,
		writeTopics: userInfo.Topics.Write,
		withToken:   false,
	}
}

func createUserWithToken(accessToken string) *authenticatedUser {

	ctx := context.TODO()
	tokenReview := &v1.TokenReview{
		Spec: v1.TokenReviewSpec{
			Token:     accessToken,
			Audiences: authConfig.Audiences,
		},
	}
	result, err := clientset.AuthenticationV1().TokenReviews().Create(ctx, tokenReview, metav1.CreateOptions{})

	if err != nil {
		log.Warnf("k8s token review failed, %s", err.Error())
		return nil
	}

	if !result.Status.Authenticated {
		log.Warnf("k8s token returned unauthenticated result: %s", result.Status.Error)
		return nil
	}

	matches := serviceAccountRegex.FindStringSubmatch(result.Status.User.Username)
	if matches == nil {
		log.Warnf("Username %s does not seem to refer to a k8s service account. Cannot authorise MQTT access.", result.Status.User.Username)
		return nil
	}
	matchedNamespace := matches[serviceAccountRegex.SubexpIndex("Namespace")]
	matchedUsername := matches[serviceAccountRegex.SubexpIndex("AccountName")]

	if matchedNamespace != authConfig.Namespace {
		log.Warnf("User %s lives in namespace %s, not %s.", result.Status.User.Username, matchedNamespace, authConfig.Namespace)
		return nil
	}

	info, err := getUserInfo(matchedUsername)

	if err != nil {
		return nil
	}

	return &authenticatedUser{
		username:    matchedUsername,
		createdAt:   time.Now(),
		updatedAt:   time.Now(),
		readTopics:  info.Topics.Read,
		writeTopics: info.Topics.Write,
		withToken:   true,
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

	// Version of the plugin
	version = "v0.0.1"

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
		cacheDuration = 0
	}

	authConfig = K8sAuthConfig{
		Namespace: namespace,
		Audiences: audienceSplit,
	}

	userCache = make(map[string]authenticatedUser)

	return nil
}

func GetUser(username string, password string, clientid string) bool {
	// Get token for the credentials and verify the user
	log.Infof("Checking user with k8s plugin.")
	var user *authenticatedUser
	if username == "__token__" {
		user = createUserWithToken(password)
	} else {
		user = createUserWithPassword(username, password)
	}

	if user != nil {
		userCache[clientid] = *user
		return true
	}
	return false
}

func refreshUserCacheIfStale(username string, clientId string) *authenticatedUser {
	cache, ok := userCache[clientId]
	if !ok {
		log.Warnf("Have no entry in user cache for user %s", username)
		return nil
	}

	if !cacheIsValid(&cache) {
		info, err := getUserInfo(cache.username)

		if err != nil {
			log.Errorf("Failed to receive UserInfo for user %s: %s", cache.username, err)
			return nil
		}

		cache.readTopics = info.Topics.Read
		cache.writeTopics = info.Topics.Write
		cache.updatedAt = time.Now()
	} else {
		log.Debug("Get userinfo from cache")
	}
	return &cache
}

func GetSuperuser(username string) bool {
	// we don't do admin users
	return false
}

func CheckAcl(username, topic, clientid string, acc int32) bool {
	// Function that checks if the user has the right to access a address
	log.Debugf("Checking if user %s is allowed to access topic %s with access %d.", username, topic, acc)

	cache := refreshUserCacheIfStale(username, clientid)
	if cache == nil {
		return false
	}

	res := checkAccessToTopic(topic, acc, cache, username, clientid)
	log.Debugf("ACL check was %t", res)
	return res
}

func Halt() {
	// Do whatever cleanup is needed.
}
