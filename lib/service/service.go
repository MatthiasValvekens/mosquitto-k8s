package service

import (
	"context"
	"errors"
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

type K8sAuthService struct {
	authClient    acct_info.K8sAccountsClient
	userDataCache cache.UserDataCache
	ctx           context.Context
}

func NewService(authOpts map[string]string) (*K8sAuthService, error) {
	var result = K8sAuthService{}
	config, err := rest.InClusterConfig()

	if err != nil {
		return nil, errors.New("this plugin only works in a k8s pod")
	}

	apiClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Join(errors.New("failed to initialise k8s clientset"), err)
	}

	namespace, ok := authOpts["k8s_namespace"]
	if !ok {
		namespaceBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		namespace = string(namespaceBytes)
		if err != nil {
			return nil, errors.Join(errors.New("no k8s_namespace specified, failed to read it from the pod"), err)

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
	result.authClient = acct_info.NewClient(authConfig, apiClient)
	cacheDurationSeconds, ok := authOpts["k8s_cache_duration"]
	var cacheValidity time.Duration
	var cacheTimeout time.Duration
	if ok {
		durationInt, err := strconv.Atoi(cacheDurationSeconds)
		if err != nil {
			return nil, errors.Join(errors.New("failed to parse k8s_cache_duration as an integer number of seconds"), err)
		}
		cacheValidity = time.Duration(durationInt) * time.Second
	} else {
		return nil, errors.Join(errors.New("no k8s_cache_duration specified"), err)
	}

	sessionTimeoutSeconds, ok := authOpts["k8s_pruning_interval"]
	if ok {
		durationInt, err := strconv.Atoi(sessionTimeoutSeconds)
		if err != nil {
			return nil, errors.Join(errors.New("failed to parse k8s_pruning_interval as an integer number of seconds"), err)
		}
		cacheTimeout = time.Duration(durationInt) * time.Second
	} else {
		return nil, errors.Join(errors.New("no k8s_pruning_interval specified"), err)
	}
	result.userDataCache = cache.NewUserDataCache(cacheValidity, cacheTimeout)
	result.ctx = context.Background()
	return &result, nil
}

func (s *K8sAuthService) Login(username string, password string) *string {
	var info *acct_info.ServiceAccountMetadata

	// we always refresh the cache on a new connection
	if username == "__token__" {
		info = s.authClient.AuthenticateWithToken(s.ctx, password)
	} else {
		info = s.authClient.AuthenticateWithPassword(s.ctx, username, password)
	}

	if info != nil {
		s.userDataCache.InitEntry(*info, time.Now())
		return &info.UserName
	}
	return nil
}

func (s *K8sAuthService) CheckAcl(username string, topic string, clientid string, acc int32) bool {
	// Function that checks if the user has the right to access a topic
	log.Debugf("Checking if user %s is allowed to access topic %s with access %d.", username, topic, acc)

	user := s.userDataCache.RefreshIfStale(s.ctx, username, s.authClient)
	if user == nil {
		return false
	}

	res := user.Info.TopicAccess.CheckAccessToTopic(topic, acc, user.Info.UserName, clientid)
	log.Debugf("ACL check was %t", res)
	return res
}
