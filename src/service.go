package main

import (
	"context"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"mosquitto-go-auth-k8s/acct_info"
	"mosquitto-go-auth-k8s/cache"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var version = "v0.0.1"

var authClient acct_info.K8sAccountsClient

var userDataCache cache.UserDataCache

var ctx context.Context

func ApplyAuthConfig(authOpts map[string]string) error {
	config, err := rest.InClusterConfig()

	if err != nil {
		log.Panic("This plugin only works in a k8s pod")
	}

	apiClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panic("Failed to initialise k8s clientset")
	}

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
	}
	authConfig := acct_info.K8sAuthConfig{
		Namespace: namespace,
		Audiences: audienceSplit,
	}
	authClient = acct_info.NewClient(authConfig, apiClient)
	cacheDurationSeconds, ok := authOpts["k8s_cache_duration"]
	var cacheValidity time.Duration
	var cacheTimeout time.Duration
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

	userDataCache = cache.NewUserDataCache(cacheValidity, cacheTimeout)
	log.Infof("k8s Plugin " + version + " initialized!")

	ctx = context.Background()

	return nil
}

func Login(username string, password string) *string {
	var info *acct_info.ServiceAccountMetadata

	// we always refresh the cache on a new connection
	if username == "__token__" {
		info = authClient.AuthenticateWithToken(ctx, password)
	} else {
		info = authClient.AuthenticateWithPassword(ctx, username, password)
	}

	if info != nil {
		userDataCache.InitEntry(*info, time.Now())
		return &info.UserName
	}
	return nil
}

func CheckAcl(username string, topic string, clientid string, acc int32) bool {
	// Function that checks if the user has the right to access a topic
	log.Debugf("Checking if user %s is allowed to access topic %s with access %d.", username, topic, acc)

	user := userDataCache.RefreshIfStale(ctx, username, authClient)
	if user == nil {
		return false
	}

	res := user.Info.TopicAccess.CheckAccessToTopic(topic, acc, user.Info.UserName, clientid)
	log.Debugf("ACL check was %t", res)
	return res
}
