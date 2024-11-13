package acct_info

import (
	"context"
	"fmt"
	"github.com/google/go-cmp/cmp"
	authv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	testclient "k8s.io/client-go/kubernetes/fake"
	k8stest "k8s.io/client-go/testing"
	"mosquitto-go-auth-k8s/topics"
	"testing"
	"time"
)

const testAcctName = "foo"

func serviceAcct(name string, annots map[string]string) *v1.ServiceAccount {
	return &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annots,
		},
	}
}

var config = K8sAuthConfig{
	Namespace: "test",
	Audiences: []string{"mosquitto"},
}

func TestK8sAccountsClient_GetAccountMetadata(t *testing.T) {
	cases := []struct {
		annots   map[string]string
		expected ServiceAccountMetadata
	}{
		{
			map[string]string{
				AllowReadTopicsAnnot: "quux,bar/baz",
			},
			ServiceAccountMetadata{
				UserName: testAcctName,
				TopicAccess: topics.TopicAccess{
					ReadPatterns:  []string{"quux", "bar/baz"},
					WritePatterns: []string{},
				},
				passwordSecretRef: "",
			},
		},
		{
			map[string]string{},
			ServiceAccountMetadata{
				UserName:          testAcctName,
				TopicAccess:       topics.TopicAccess{[]string{}, []string{}},
				passwordSecretRef: "",
			},
		},
		{
			map[string]string{
				AllowWriteTopicsAnnot: "quux,bar/baz",
			},
			ServiceAccountMetadata{
				UserName: testAcctName,
				TopicAccess: topics.TopicAccess{
					ReadPatterns:  []string{},
					WritePatterns: []string{"quux", "bar/baz"},
				},
				passwordSecretRef: "",
			},
		},
		{
			map[string]string{
				AllowReadTopicsAnnot:  "blah",
				AllowWriteTopicsAnnot: "quux,bar/baz",
			},
			ServiceAccountMetadata{
				UserName: testAcctName,
				TopicAccess: topics.TopicAccess{
					ReadPatterns:  []string{"blah"},
					WritePatterns: []string{"quux", "bar/baz"},
				},
				passwordSecretRef: "",
			},
		},
		{
			map[string]string{
				AllowReadTopicsAnnot:   "blah",
				PasswordSecretRefAnnot: "creds",
			},
			ServiceAccountMetadata{
				UserName: testAcctName,
				TopicAccess: topics.TopicAccess{
					ReadPatterns:  []string{"blah"},
					WritePatterns: []string{},
				},
				passwordSecretRef: "creds",
			},
		},
	}

	for _, c := range cases {
		client := &K8sAccountsClient{
			Config:    config,
			apiClient: testclient.NewClientset(),
			timeout:   10 * time.Second,
		}

		ctx := context.TODO()
		t.Run(fmt.Sprintf("expected:%v", c.expected), func(t *testing.T) {
			_, err := client.apiClient.CoreV1().ServiceAccounts(config.Namespace).Create(
				ctx,
				serviceAcct(testAcctName, c.annots),
				metav1.CreateOptions{},
			)
			if err != nil {
				t.Fatalf("Failed to create ServiceAccount: %v", err)
			}
			metadata, err := client.GetAccountMetadata(ctx, testAcctName)
			if err != nil {
				t.Fatalf("Failed to retrieve ServiceAccount metadata: %v", err)
				return
			}
			if !cmp.Equal(*metadata, c.expected, cmp.AllowUnexported(ServiceAccountMetadata{})) {
				t.Fatalf("Expected %v but got %v", c.expected, *metadata)
			}
		})
	}

}

func TestK8sAccountsClient_getPassword(t *testing.T) {
	ctx := context.TODO()
	t.Run("read password", func(t *testing.T) {
		client := &K8sAccountsClient{
			Config:    config,
			apiClient: testclient.NewClientset(),
			timeout:   10 * time.Second,
		}
		_, err := client.apiClient.CoreV1().ServiceAccounts(config.Namespace).Create(
			ctx,
			serviceAcct(testAcctName, map[string]string{PasswordSecretRefAnnot: "creds"}),
			metav1.CreateOptions{},
		)
		if err != nil {
			t.Fatalf("Failed to create ServiceAccount: %v", err)
		}
		_, err = client.apiClient.CoreV1().Secrets(config.Namespace).Create(
			ctx,
			&v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "creds",
				},
				Data: map[string][]byte{
					MQTTPasswordKey: []byte("pass"),
				},
			},
			metav1.CreateOptions{},
		)
		if err != nil {
			t.Fatalf("Failed to create Secret: %v", err)
		}
		info, err := client.getAccountInfo(ctx, testAcctName)
		if err != nil {
			t.Fatalf("Failed to retrieve ServiceAccount metadata: %v", err)
			return
		}
		if info.directPassword != "pass" {
			t.Fatalf("Password not found")
		}
	})
	t.Run("read password when there is no secret", func(t *testing.T) {
		client := &K8sAccountsClient{
			Config:    config,
			apiClient: testclient.NewClientset(),
			timeout:   10 * time.Second,
		}
		_, err := client.apiClient.CoreV1().ServiceAccounts(config.Namespace).Create(
			ctx,
			serviceAcct(testAcctName, map[string]string{PasswordSecretRefAnnot: "creds"}),
			metav1.CreateOptions{},
		)
		if err != nil {
			t.Fatalf("Failed to create ServiceAccount: %v", err)
		}
		info, err := client.getAccountInfo(ctx, testAcctName)
		if err != nil {
			t.Fatalf("Failed to retrieve ServiceAccount metadata: %v", err)
			return
		}
		if info.directPassword != "" {
			t.Fatalf("Password unexpectedly set")
		}
	})

	t.Run("read password when the secret does not have the expected key", func(t *testing.T) {
		client := &K8sAccountsClient{
			Config:    config,
			apiClient: testclient.NewClientset(),
			timeout:   10 * time.Second,
		}
		_, err := client.apiClient.CoreV1().ServiceAccounts(config.Namespace).Create(
			ctx,
			serviceAcct(testAcctName, map[string]string{PasswordSecretRefAnnot: "creds"}),
			metav1.CreateOptions{},
		)
		if err != nil {
			t.Fatalf("Failed to create ServiceAccount: %v", err)
		}
		_, err = client.apiClient.CoreV1().Secrets(config.Namespace).Create(
			ctx,
			&v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "creds",
				},
				Data: map[string][]byte{
					"something": []byte("pass"),
				},
			},
			metav1.CreateOptions{},
		)
		if err != nil {
			t.Fatalf("Failed to create Secret: %v", err)
		}
		info, err := client.getAccountInfo(ctx, testAcctName)
		if err != nil {
			t.Fatalf("Failed to retrieve ServiceAccount metadata: %v", err)
			return
		}
		if info.directPassword != "" {
			t.Fatalf("Expected empty password")
		}
	})
}

func TestK8sAccountsClient_authWithPassword(t *testing.T) {
	ctx := context.TODO()
	client := &K8sAccountsClient{
		Config:    config,
		apiClient: testclient.NewClientset(),
		timeout:   10 * time.Second,
	}
	_, err := client.apiClient.CoreV1().ServiceAccounts(config.Namespace).Create(
		ctx,
		serviceAcct(testAcctName, map[string]string{PasswordSecretRefAnnot: "creds"}),
		metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatalf("Failed to create ServiceAccount: %v", err)
	}
	_, err = client.apiClient.CoreV1().Secrets(config.Namespace).Create(
		ctx,
		&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "creds",
			},
			Data: map[string][]byte{
				MQTTPasswordKey: []byte("pass"),
			},
		},
		metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatalf("Failed to create Secret: %v", err)
	}
	t.Run("correct password", func(t *testing.T) {
		meta := client.AuthenticateWithPassword(ctx, testAcctName, "pass")
		if meta == nil {
			t.Fatal()
		}
	})
	t.Run("incorrect password", func(t *testing.T) {
		meta := client.AuthenticateWithPassword(ctx, testAcctName, "wrong")
		if meta != nil {
			t.Fatal(meta)
		}
	})

}
func TestK8sAccountsClient_authWithPasswordUnavailable(t *testing.T) {
	const testAcctName = "foo"

	ctx := context.TODO()
	client := &K8sAccountsClient{
		Config:    config,
		apiClient: testclient.NewClientset(),
		timeout:   10 * time.Second,
	}
	_, err := client.apiClient.CoreV1().ServiceAccounts(config.Namespace).Create(
		ctx,
		serviceAcct(testAcctName, map[string]string{}),
		metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatalf("Failed to create ServiceAccount: %v", err)
	}
	t.Run("password login disabled", func(t *testing.T) {
		meta := client.AuthenticateWithPassword(ctx, testAcctName, "pass")
		if meta != nil {
			t.Fatal()
		}
	})

}

func TestK8sAccountsClient_authWithToken(t *testing.T) {

	ctx := context.TODO()
	// use deprecated client set because the new one is too clever and doesn't work for token review
	//goland:noinspection ALL
	var testClient = testclient.NewSimpleClientset()
	client := &K8sAccountsClient{
		Config:    config,
		apiClient: testClient,
		timeout:   10 * time.Second,
	}
	testClient.PrependReactor("create", "tokenreviews", func(action k8stest.Action) (bool, runtime.Object, error) {
		obj := action.(k8stest.CreateAction).GetObject()
		review, _ := obj.(*authv1.TokenReview)
		review.Status = authv1.TokenReviewStatus{
			Authenticated: true,
			Audiences:     config.Audiences,
			User: authv1.UserInfo{
				Username: fmt.Sprintf("system:serviceaccount:%s:%s", config.Namespace, testAcctName),
			},
		}

		return false, nil, nil
	})
	_, err := client.apiClient.CoreV1().ServiceAccounts(config.Namespace).Create(
		ctx,
		serviceAcct(testAcctName, map[string]string{AllowReadTopicsAnnot: "notifications"}),
		metav1.CreateOptions{},
	)

	if err != nil {
		t.Fatalf("Failed to create ServiceAccount: %v", err)
	}
	t.Run("auth with token", func(t *testing.T) {
		meta := *client.AuthenticateWithToken(ctx, "token")
		expectedMeta := ServiceAccountMetadata{
			UserName: "foo",
			TopicAccess: topics.TopicAccess{
				ReadPatterns:  []string{"notifications"},
				WritePatterns: []string{},
			},
			passwordSecretRef: "",
		}
		if !cmp.Equal(meta, expectedMeta, cmp.AllowUnexported(ServiceAccountMetadata{})) {
			t.Fatalf("Expected %v but got %v", expectedMeta, meta)
		}
	})

}
func TestK8sAccountsClient_authWithTokenFailed(t *testing.T) {

	ctx := context.TODO()
	responses := []authv1.TokenReviewStatus{
		{
			Authenticated: true,
			Audiences:     config.Audiences,
			User: authv1.UserInfo{
				Username: fmt.Sprintf("system:serviceaccount:%s:%s", "another-namespace", testAcctName),
			},
		},
		{
			Authenticated: false,
			Audiences:     config.Audiences,
		},
		{
			Authenticated: true,
			Audiences:     config.Audiences,
			User: authv1.UserInfo{
				Username: fmt.Sprintf("system:serviceaccount:%s:%s", config.Namespace, "doesntexist"),
			},
		},
	}
	for ix, response := range responses {
		// use deprecated client set because the new one is too clever and doesn't work for token review
		//goland:noinspection ALL
		var testClient = testclient.NewSimpleClientset()
		client := &K8sAccountsClient{
			Config:    config,
			apiClient: testClient,
			timeout:   10 * time.Second,
		}
		testClient.PrependReactor("create", "tokenreviews", func(action k8stest.Action) (bool, runtime.Object, error) {
			obj := action.(k8stest.CreateAction).GetObject()
			review, _ := obj.(*authv1.TokenReview)
			review.Status = response

			return false, nil, nil
		})
		_, err := client.apiClient.CoreV1().ServiceAccounts(config.Namespace).Create(
			ctx,
			serviceAcct(testAcctName, map[string]string{AllowReadTopicsAnnot: "notifications"}),
			metav1.CreateOptions{},
		)

		if err != nil {
			t.Fatalf("Failed to create ServiceAccount: %v", err)
		}
		t.Run(fmt.Sprintf("case %d", ix), func(t *testing.T) {
			meta := client.AuthenticateWithToken(ctx, "token")
			if meta != nil {
				t.Fatalf("Expected auth to fail, but got %v", *meta)
			}

		})

	}

}
