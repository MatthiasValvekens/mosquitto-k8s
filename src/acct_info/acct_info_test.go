package acct_info

import (
	"context"
	"fmt"
	"github.com/google/go-cmp/cmp"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testclient "k8s.io/client-go/kubernetes/fake"
	"testing"
	"time"
)

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
	const testAcctName = "foo"
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
				TopicAccess: TopicAccess{
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
				TopicAccess:       TopicAccess{[]string{}, []string{}},
				passwordSecretRef: "",
			},
		},
		{
			map[string]string{
				AllowWriteTopicsAnnot: "quux,bar/baz",
			},
			ServiceAccountMetadata{
				UserName: testAcctName,
				TopicAccess: TopicAccess{
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
				TopicAccess: TopicAccess{
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
				TopicAccess: TopicAccess{
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
	const testAcctName = "foo"

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
	const testAcctName = "foo"

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
