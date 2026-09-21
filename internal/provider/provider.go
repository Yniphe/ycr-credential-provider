package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	APIVersion                      = "credentialprovider.kubelet.k8s.io/v1"
	DefaultRegistryHost             = "cr.yandex"
	DefaultTokenURL                 = "https://auth.yandex.cloud/oauth/token"
	DefaultServiceAccountAnnotation = "yandex.cloud/federated-yc-service-account-id"
	maxResponseSize                 = 1 << 20
)

const (
	grantType        = "urn:ietf:params:oauth:grant-type:token-exchange"
	requestedType    = "urn:ietf:params:oauth:token-type:access_token"
	subjectTokenType = "urn:ietf:params:oauth:token-type:id_token"
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
	endpoint, err := url.Parse(c.TokenURL)
	if err != nil {
		return fmt.Errorf("invalid token URL: %w", err)
	}
	if endpoint.Scheme != "https" || endpoint.Host == "" {
		return errors.New("token URL must be an absolute HTTPS URL")
	}
	if endpoint.User != nil {
		return errors.New("token URL must not contain user information")
	}
	if strings.TrimSpace(c.RegistryHost) == "" || strings.ContainsAny(c.RegistryHost, "/ \\\t\r\n") {
		return errors.New("registry host must be a hostname without a path")
	}
	if strings.TrimSpace(c.ServiceAccountAnnotation) == "" && strings.TrimSpace(c.ServiceAccountID) == "" {
		return errors.New("service account annotation or service account ID must be configured")
	}
	if c.Timeout <= 0 {
		return errors.New("timeout must be positive")
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

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type Client struct {
	config Config
	http   *http.Client
}

func New(config Config, httpClient *http.Client) *Client {
	return &Client{config: config, http: httpClient}
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
	if err := validateServiceAccountID(serviceAccountID); err != nil {
		return CredentialProviderResponse{}, err
	}

	token, err := c.exchange(ctx, serviceAccountID, request.ServiceAccountToken)
	if err != nil {
		return CredentialProviderResponse{}, err
	}

	cacheDuration := time.Duration(token.ExpiresIn) * time.Second
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

func (c *Client) exchange(ctx context.Context, serviceAccountID, subjectToken string) (tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", grantType)
	form.Set("requested_token_type", requestedType)
	form.Set("audience", serviceAccountID)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", subjectTokenType)

	requestContext, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, c.config.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("create token exchange request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	if c.config.UserAgent != "" {
		request.Header.Set("User-Agent", c.config.UserAgent)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("exchange workload identity token: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("read token exchange response: %w", err)
	}
	if len(body) > maxResponseSize {
		return tokenResponse{}, errors.New("token exchange response is too large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		requestID := response.Header.Get("X-Request-Id")
		if requestID == "" {
			requestID = response.Header.Get("X-Ya-Request-Id")
		}
		if requestID != "" {
			return tokenResponse{}, fmt.Errorf("token exchange returned HTTP %d (request ID %s)", response.StatusCode, requestID)
		}
		return tokenResponse{}, fmt.Errorf("token exchange returned HTTP %d", response.StatusCode)
	}

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return tokenResponse{}, fmt.Errorf("decode token exchange response: %w", err)
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return tokenResponse{}, errors.New("token exchange response contains no access token")
	}
	if token.TokenType != "" && !strings.EqualFold(token.TokenType, "Bearer") {
		return tokenResponse{}, fmt.Errorf("token exchange response contains unsupported token type %q", token.TokenType)
	}
	if token.ExpiresIn <= 0 {
		return tokenResponse{}, errors.New("token exchange response contains an invalid expires_in value")
	}
	return token, nil
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

func validateServiceAccountID(value string) error {
	if value == "" {
		return fmt.Errorf("Yandex Cloud service account ID is required; set --service-account-id or annotation %q", DefaultServiceAccountAnnotation)
	}
	if len(value) > 128 {
		return errors.New("Yandex Cloud service account ID is too long")
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return fmt.Errorf("Yandex Cloud service account ID contains invalid character %s", strconv.QuoteRune(character))
		}
	}
	return nil
}
