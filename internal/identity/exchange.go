package identity

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
	DefaultTokenURL  = "https://auth.yandex.cloud/oauth/token"
	maxResponseSize  = 1 << 20
	grantType        = "urn:ietf:params:oauth:grant-type:token-exchange"
	requestedType    = "urn:ietf:params:oauth:token-type:access_token"
	subjectTokenType = "urn:ietf:params:oauth:token-type:id_token"
)

type Config struct {
	TokenURL  string
	Timeout   time.Duration
	UserAgent string
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
	if c.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	return nil
}

type Token struct {
	AccessToken string
	ExpiresIn   time.Duration
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

func (c *Client) Exchange(ctx context.Context, serviceAccountID, subjectToken string) (Token, error) {
	if err := ValidateServiceAccountID(serviceAccountID); err != nil {
		return Token{}, err
	}
	if strings.TrimSpace(subjectToken) == "" {
		return Token{}, errors.New("service account token is required")
	}

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
		return Token{}, fmt.Errorf("create token exchange request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	if c.config.UserAgent != "" {
		request.Header.Set("User-Agent", c.config.UserAgent)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return Token{}, fmt.Errorf("exchange workload identity token: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return Token{}, fmt.Errorf("read token exchange response: %w", err)
	}
	if len(body) > maxResponseSize {
		return Token{}, errors.New("token exchange response is too large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Token{}, responseError("token exchange", response, "")
	}

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return Token{}, fmt.Errorf("decode token exchange response: %w", err)
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return Token{}, errors.New("token exchange response contains no access token")
	}
	if token.TokenType != "" && !strings.EqualFold(token.TokenType, "Bearer") {
		return Token{}, fmt.Errorf("token exchange response contains unsupported token type %q", token.TokenType)
	}
	if token.ExpiresIn <= 0 {
		return Token{}, errors.New("token exchange response contains an invalid expires_in value")
	}

	return Token{AccessToken: token.AccessToken, ExpiresIn: time.Duration(token.ExpiresIn) * time.Second}, nil
}

func ValidateServiceAccountID(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("Yandex Cloud service account ID is required")
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

func responseError(operation string, response *http.Response, detail string) error {
	requestID := response.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = response.Header.Get("X-Ya-Request-Id")
	}
	if requestID != "" {
		return fmt.Errorf("%s returned HTTP %d (request ID %s)%s", operation, response.StatusCode, requestID, detail)
	}
	return fmt.Errorf("%s returned HTTP %d%s", operation, response.StatusCode, detail)
}
