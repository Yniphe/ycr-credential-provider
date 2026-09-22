package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Yniphe/ycr-credential-provider/internal/identity"
)

const (
	APIVersion                      = "credentialprovider.kubelet.k8s.io/v1"
	DefaultRegistryHost             = "cr.yandex"
	DefaultTokenURL                 = identity.DefaultTokenURL
	DefaultServiceAccountAnnotation = "yandex.cloud/federated-yc-service-account-id"
)

type Config struct {
	TokenURL                 string
	RegistryHost             string
	ServiceAccountID         string
	ServiceAccountAnnotation string
	Timeout                  time.Duration
	CacheSafetyMargin        time.Duration
	UserAgent                string
}

func (c Config) Validate() error {
	if err := (identity.Config{TokenURL: c.TokenURL, Timeout: c.Timeout}).Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(c.RegistryHost) == "" || strings.ContainsAny(c.RegistryHost, "/ \\\t\r\n") {
		return errors.New("registry host must be a hostname without a path")
	}
	if strings.TrimSpace(c.ServiceAccountAnnotation) == "" && strings.TrimSpace(c.ServiceAccountID) == "" {
		return errors.New("service account annotation or service account ID must be configured")
	}
	if c.CacheSafetyMargin < 0 {
		return errors.New("cache safety margin must not be negative")
	}
	return nil
}

type CredentialProviderRequest struct {
	APIVersion                string            `json:"apiVersion"`
	Kind                      string            `json:"kind"`
	Image                     string            `json:"image"`
	ServiceAccountToken       string            `json:"serviceAccountToken"`
	ServiceAccountAnnotations map[string]string `json:"serviceAccountAnnotations"`
}

type CredentialProviderResponse struct {
	APIVersion    string                `json:"apiVersion"`
	Kind          string                `json:"kind"`
	CacheKeyType  string                `json:"cacheKeyType"`
	CacheDuration string                `json:"cacheDuration"`
	Auth          map[string]AuthConfig `json:"auth"`
}

type AuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Client struct {
	config   Config
	identity *identity.Client
}

func New(config Config, httpClient *http.Client) *Client {
	return &Client{
		config: config,
		identity: identity.New(identity.Config{
			TokenURL:  config.TokenURL,
			Timeout:   config.Timeout,
			UserAgent: config.UserAgent,
		}, httpClient),
	}
}

func (c *Client) Provide(ctx context.Context, request CredentialProviderRequest) (CredentialProviderResponse, error) {
	if request.APIVersion != APIVersion {
		return CredentialProviderResponse{}, fmt.Errorf("unsupported apiVersion %q", request.APIVersion)
	}
	if request.Kind != "CredentialProviderRequest" {
		return CredentialProviderResponse{}, fmt.Errorf("unsupported kind %q", request.Kind)
	}
	registry, err := registryFromImage(request.Image)
	if err != nil {
		return CredentialProviderResponse{}, err
	}
	registryHost := strings.ToLower(strings.TrimSpace(c.config.RegistryHost))
	if registry != registryHost {
		return CredentialProviderResponse{}, fmt.Errorf("image registry %q is not configured registry %q", registry, c.config.RegistryHost)
	}
	if strings.TrimSpace(request.ServiceAccountToken) == "" {
		return CredentialProviderResponse{}, errors.New("service account token is required")
	}

	serviceAccountID := strings.TrimSpace(c.config.ServiceAccountID)
	if serviceAccountID == "" {
		serviceAccountID = strings.TrimSpace(request.ServiceAccountAnnotations[c.config.ServiceAccountAnnotation])
	}
	token, err := c.identity.Exchange(ctx, serviceAccountID, request.ServiceAccountToken)
	if err != nil {
		return CredentialProviderResponse{}, err
	}

	cacheDuration := token.ExpiresIn
	if cacheDuration > c.config.CacheSafetyMargin {
		cacheDuration -= c.config.CacheSafetyMargin
	} else {
		cacheDuration = 0
	}

	return CredentialProviderResponse{
		APIVersion:    APIVersion,
		Kind:          "CredentialProviderResponse",
		CacheKeyType:  "Registry",
		CacheDuration: cacheDuration.String(),
		Auth: map[string]AuthConfig{
			registryHost: {
				Username: "iam",
				Password: token.AccessToken,
			},
		},
	}, nil
}

func registryFromImage(image string) (string, error) {
	image = strings.TrimSpace(image)
	if image == "" {
		return "", errors.New("image is required")
	}
	registry, remainder, ok := strings.Cut(image, "/")
	if !ok || registry == "" || remainder == "" {
		return "", fmt.Errorf("image %q must include an explicit registry and repository", image)
	}
	return strings.ToLower(registry), nil
}
