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
)

var serviceAccountRegex = regexp.MustCompile(`system:serviceaccount:(?P<Namespace>[-_a-zA-Z0-9]+):(?P<AccountName>[-_a-zA-Z0-9]+)`)

type TopicAccess struct {
	ReadPatterns  []string
	WritePatterns []string
}

type ServiceAccountMetadata struct {
	UserName    string
	TopicAccess TopicAccess
}

type ServiceAccountAuthInfo struct {
	Meta           ServiceAccountMetadata
	directPassword string
}

type K8sAuthConfig struct {
	Namespace string
	Audiences []string
}

type K8sAccountsClient struct {
	Config    K8sAuthConfig
	apiClient kubernetes.Clientset
}

func NewClient(config K8sAuthConfig, apiClient kubernetes.Clientset) K8sAccountsClient {
	return K8sAccountsClient{
		Config:    config,
		apiClient: apiClient,
	}
}

func (client *K8sAccountsClient) GetAccountInfo(accountName string) (*ServiceAccountAuthInfo, error) {
	info := ServiceAccountAuthInfo{
		Meta: ServiceAccountMetadata{UserName: accountName},
	}

	ctx := context.TODO()

	account, err := client.apiClient.CoreV1().ServiceAccounts(client.Config.Namespace).Get(ctx, accountName, metav1.GetOptions{})

	if err != nil {
		log.Warnf("Error fetching account %s: %s", account, err.Error())
		return nil, err
	}

	annots := account.Annotations
	passwordSecretRef, ok := annots["mqtt.dev.mvalvekens.be/password-secret"]

	info.directPassword = ""
	if ok {
		log.Debugf("User %s has password login enabled, reading from secret %s", accountName, passwordSecretRef)
		secret, err := client.apiClient.CoreV1().Secrets(client.Config.Namespace).Get(ctx, passwordSecretRef, metav1.GetOptions{})
		if err == nil {
			passwordBytes, ok := secret.Data["MQTT_PASSWORD"]
			if ok {
				info.directPassword = string(passwordBytes)
			}
		}
	}

	readTopics, ok := annots["mqtt.dev.mvalvekens.be/allow-read"]
	if ok {
		log.Debugf("User %s has read access to %s", accountName, readTopics)
		info.Meta.TopicAccess.ReadPatterns = strings.Split(strings.Replace(readTopics, " ", "", -1), ",")
	} else {
		log.Debugf("User %s does not have read access to any topics", accountName)
		info.Meta.TopicAccess.ReadPatterns = []string{}
	}
	writeTopics, ok := annots["mqtt.dev.mvalvekens.be/allow-write"]
	if ok {
		log.Debugf("User %s has write access to %s", accountName, writeTopics)
		info.Meta.TopicAccess.WritePatterns = strings.Split(strings.Replace(writeTopics, " ", "", -1), ",")
	} else {
		log.Debugf("User %s does not have write access to any topics", accountName)
		info.Meta.TopicAccess.WritePatterns = []string{}
	}

	return &info, nil
}

func (client *K8sAccountsClient) AuthenticateWithPassword(username string, password string) *ServiceAccountMetadata {
	// legacy IoT clients with a password that is passed around in the clear

	userInfo, err := client.GetAccountInfo(username)
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

	return &userInfo.Meta
}

func (client *K8sAccountsClient) AuthenticateWithToken(accessToken string) *ServiceAccountMetadata {
	ctx := context.TODO()
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
	info, err := client.GetAccountInfo(matchedUsername)

	if err != nil {
		log.Warnf("Failed to fetch user data for %s, %s", result.Status.User.Username, err)
	}
	return &info.Meta
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
