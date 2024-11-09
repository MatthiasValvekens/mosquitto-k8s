package main

import (
	"context"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"regexp"
	"strings"
)

var serviceAccountRegex = regexp.MustCompile(`system:serviceaccount:(?P<Namespace>[-_a-zA-Z0-9]+):(?P<AccountName>[-_a-zA-Z0-9]+)`)

type ServiceAccountMetadata struct {
	Username    string
	TopicAccess struct {
		ReadPatterns  []string
		WritePatterns []string
	}
	DirectPassword string
}

func getAccountMetadata(accountName string) (*ServiceAccountMetadata, error) {
	info := ServiceAccountMetadata{Username: accountName}

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
		info.TopicAccess.ReadPatterns = strings.Split(strings.Replace(readTopics, " ", "", -1), ",")
	} else {
		log.Debugf("User %s does not have read access to any topics", accountName)
		info.TopicAccess.ReadPatterns = []string{}
	}
	writeTopics, ok := annots["mqtt.dev.mvalvekens.be/allow-write"]
	if ok {
		log.Debugf("User %s has write access to %s", accountName, writeTopics)
		info.TopicAccess.WritePatterns = strings.Split(strings.Replace(writeTopics, " ", "", -1), ",")
	} else {
		log.Debugf("User %s does not have write access to any topics", accountName)
		info.TopicAccess.WritePatterns = []string{}
	}

	return &info, nil
}

func authenticateServiceAccount(accessToken string) *ServiceAccountMetadata {
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
	info, err := getAccountMetadata(matchedUsername)

	if err != nil {
		log.Warnf("Failed to fetch user data for %s, %s", result.Status.User.Username, err)
	}
	return info
}
