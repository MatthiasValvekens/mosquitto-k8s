package acct_info

import (
	"context"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"mosquitto-go-auth-k8s/topics"
	"regexp"
	"strings"
	"time"
)

var serviceAccountRegex = regexp.MustCompile(`system:serviceaccount:(?P<Namespace>[-_a-zA-Z0-9]+):(?P<AccountName>[-_a-zA-Z0-9]+)`)

type ServiceAccountMetadata struct {
	UserName    string
	TopicAccess struct {
		ReadPatterns  []string
		WritePatterns []string
	}
	passwordSecretRef string
}

type serviceAccountAuthInfo struct {
	meta           ServiceAccountMetadata
	directPassword string
}

type K8sAuthConfig struct {
	Namespace string
	Audiences []string
}

type K8sAccountsClient struct {
	Config    K8sAuthConfig
	apiClient kubernetes.Interface
	timeout   time.Duration
}

func NewClient(config K8sAuthConfig, apiClient kubernetes.Interface) K8sAccountsClient {
	return K8sAccountsClient{
		Config:    config,
		apiClient: apiClient,
		timeout:   10 * time.Second, // TODO make configurable
	}
}

func (client *K8sAccountsClient) GetAccountMetadata(accountName string) (*ServiceAccountMetadata, error) {
	ctx, cancelFunc := context.WithTimeout(context.TODO(), client.timeout)
	defer cancelFunc()
	return client.getAccountMetadata(ctx, accountName)
}

func (client *K8sAccountsClient) getAccountMetadata(ctx context.Context, accountName string) (*ServiceAccountMetadata, error) {
	meta := ServiceAccountMetadata{UserName: accountName}
	account, err := client.apiClient.CoreV1().ServiceAccounts(client.Config.Namespace).Get(ctx, accountName, metav1.GetOptions{})

	if err != nil {
		log.Warnf("Error fetching account %s: %s", account, err.Error())
		return nil, err
	}

	annots := account.Annotations
	passwordSecretRef, ok := annots["mqtt.dev.mvalvekens.be/password-secret"]
	if ok {
		meta.passwordSecretRef = passwordSecretRef
	} else {
		meta.passwordSecretRef = ""
	}

	readTopics, ok := annots["mqtt.dev.mvalvekens.be/allow-read"]
	if ok {
		log.Debugf("User %s has read access to %s", accountName, readTopics)
		meta.TopicAccess.ReadPatterns = strings.Split(strings.Replace(readTopics, " ", "", -1), ",")
	} else {
		log.Debugf("User %s does not have read access to any topics", accountName)
		meta.TopicAccess.ReadPatterns = []string{}
	}
	writeTopics, ok := annots["mqtt.dev.mvalvekens.be/allow-write"]
	if ok {
		log.Debugf("User %s has write access to %s", accountName, writeTopics)
		meta.TopicAccess.WritePatterns = strings.Split(strings.Replace(writeTopics, " ", "", -1), ",")
	} else {
		log.Debugf("User %s does not have write access to any topics", accountName)
		meta.TopicAccess.WritePatterns = []string{}
	}
	return &meta, nil
}

func (client *K8sAccountsClient) getAccountInfo(ctx context.Context, accountName string) (*serviceAccountAuthInfo, error) {
	meta, err := client.getAccountMetadata(ctx, accountName)

	if err != nil {
		return nil, err
	}

	info := serviceAccountAuthInfo{meta: *meta}
	info.directPassword = ""
	if meta.passwordSecretRef != "" {
		log.Debugf("User %s has password login enabled, reading from secret %s", accountName, meta.passwordSecretRef)
		secret, err := client.apiClient.CoreV1().Secrets(client.Config.Namespace).Get(ctx, meta.passwordSecretRef, metav1.GetOptions{})
		if err == nil {
			passwordBytes, ok := secret.Data["MQTT_PASSWORD"]
			if ok {
				info.directPassword = string(passwordBytes)
			}
		}
	}

	return &info, nil
}

func (client *K8sAccountsClient) AuthenticateWithPassword(username string, password string) *ServiceAccountMetadata {
	// legacy IoT clients with a password that is passed around in the clear

	// TODO wire contexts up to the main loop
	ctx, cancelFunc := context.WithTimeout(context.TODO(), client.timeout)
	defer cancelFunc()
	userInfo, err := client.getAccountInfo(ctx, username)
	if err != nil || userInfo == nil {
		return nil
	}

	if userInfo.directPassword == "" {
		log.Warnf("Password login is disabled for user %s", username)
		return nil
	}

	if userInfo.directPassword != password {
		return nil
	}

	return &userInfo.meta
}

func (client *K8sAccountsClient) AuthenticateWithToken(accessToken string) *ServiceAccountMetadata {
	// TODO wire contexts up to the main loop
	ctx, cancelFunc := context.WithTimeout(context.TODO(), client.timeout)
	defer cancelFunc()
	tokenReview := &v1.TokenReview{
		Spec: v1.TokenReviewSpec{
			Token:     accessToken,
			Audiences: client.Config.Audiences,
		},
	}
	result, err := client.apiClient.AuthenticationV1().TokenReviews().Create(ctx, tokenReview, metav1.CreateOptions{})

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
		log.Warnf("UserName %s does not seem to refer to a k8s service account. Cannot authorise MQTT access.", result.Status.User.Username)
		return nil
	}
	matchedNamespace := matches[serviceAccountRegex.SubexpIndex("Namespace")]
	matchedUsername := matches[serviceAccountRegex.SubexpIndex("AccountName")]

	if matchedNamespace != client.Config.Namespace {
		log.Warnf("User %s lives in namespace %s, not %s.", result.Status.User.Username, matchedNamespace, client.Config.Namespace)
		return nil
	}
	info, err := client.getAccountInfo(ctx, matchedUsername)

	if err != nil {
		log.Warnf("Failed to fetch user data for %s, %s", result.Status.User.Username, err)
	}
	return &info.meta
}

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

func (m *ServiceAccountMetadata) CanRead(topic string, clientId string) bool {
	return isTopicInList(m.TopicAccess.ReadPatterns, topic, m.UserName, clientId)
}

func (m *ServiceAccountMetadata) CanWrite(topic string, clientId string) bool {
	return isTopicInList(m.TopicAccess.ReadPatterns, topic, m.UserName, clientId)
}

func (m *ServiceAccountMetadata) CheckAccessToTopic(topic string, acc int32, clientid string) bool {
	log.Debugf("Check for acl level %d", acc)

	// check read access
	if acc == 1 || acc == 4 {
		res := m.CanRead(topic, clientid)
		log.Debugf("ACL for read was %t", res)
		return res
	}

	// check write
	if acc == 2 {
		res := m.CanWrite(topic, clientid)
		log.Debugf("ACL for write was %t", res)
		return res
	}

	// check for readwrite
	if acc == 3 {
		res := m.CanRead(topic, clientid) && m.CanWrite(topic, clientid)
		log.Debugf("ACL for readwrite was %t", res)
		return res
	}
	return false
}
