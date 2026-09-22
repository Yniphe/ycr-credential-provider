package lockbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Yniphe/ycr-credential-provider/internal/identity"
)

const (
	DefaultAPIURL  = "https://payload.lockbox.api.cloud.yandex.net"
	maxPayloadSize = 4 << 20
)

var (
	ErrSecretNotFound   = errors.New("Lockbox secret not found")
	ErrPropertyNotFound = errors.New("Lockbox secret property not found")
)

type Config struct {
	APIURL    string
	Timeout   time.Duration
	UserAgent string
}

func (c Config) Validate() error {
	endpoint, err := url.Parse(c.APIURL)
	if err != nil {
		return fmt.Errorf("invalid Lockbox API URL: %w", err)
	}
	if endpoint.Scheme != "https" || endpoint.Host == "" {
		return errors.New("Lockbox API URL must be an absolute HTTPS URL")
	}
	if endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return errors.New("Lockbox API URL must not contain user information, query, or fragment")
	}
	if c.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	return nil
}

type Value struct {
	Text      string
	VersionID string
}

type payload struct {
	Entries   []entry `json:"entries"`
	VersionID string  `json:"versionId"`
}

type entry struct {
	Key         string `json:"key"`
	TextValue   string `json:"textValue"`
	BinaryValue string `json:"binaryValue"`
}

type Client struct {
	config Config
	base   *url.URL
	http   *http.Client
	tokens identity.TokenSource
}

func New(config Config, httpClient *http.Client, tokens identity.TokenSource) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	base, err := url.Parse(strings.TrimRight(config.APIURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse Lockbox API URL: %w", err)
	}
	if tokens == nil {
		return nil, errors.New("IAM token source is required")
	}
	return &Client{config: config, base: base, http: httpClient, tokens: tokens}, nil
}

func (c *Client) GetProperty(ctx context.Context, secretID, property string) (Value, error) {
	if err := ValidateSecretID(secretID); err != nil {
		return Value{}, err
	}
	if strings.TrimSpace(property) == "" {
		return Value{}, errors.New("Lockbox property is required")
	}

	token, err := c.tokens.Token(ctx)
	if err != nil {
		return Value{}, fmt.Errorf("get Yandex IAM token: %w", err)
	}

	endpoint := *c.base
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/lockbox/v1/secrets/" + url.PathEscape(secretID) + "/payload"
	requestContext, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return Value{}, fmt.Errorf("create Lockbox request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	if c.config.UserAgent != "" {
		request.Header.Set("User-Agent", c.config.UserAgent)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return Value{}, fmt.Errorf("request Lockbox secret: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxPayloadSize+1))
	if err != nil {
		return Value{}, fmt.Errorf("read Lockbox response: %w", err)
	}
	if len(body) > maxPayloadSize {
		return Value{}, errors.New("Lockbox response is too large")
	}
	if response.StatusCode == http.StatusNotFound {
		return Value{}, ErrSecretNotFound
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Value{}, lockboxResponseError(response)
	}

	var result payload
	if err := json.Unmarshal(body, &result); err != nil {
		return Value{}, fmt.Errorf("decode Lockbox response: %w", err)
	}
	for _, candidate := range result.Entries {
		if candidate.Key != property {
			continue
		}
		if candidate.BinaryValue != "" {
			return Value{}, fmt.Errorf("Lockbox property %q is binary; only text values are supported", property)
		}
		return Value{Text: candidate.TextValue, VersionID: result.VersionID}, nil
	}
	return Value{}, ErrPropertyNotFound
}

func ValidateSecretID(value string) error {
	if value == "" {
		return errors.New("Lockbox secret ID is required")
	}
	if len(value) > 50 {
		return errors.New("Lockbox secret ID is too long")
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return errors.New("Lockbox secret ID contains invalid characters")
		}
	}
	return nil
}

func lockboxResponseError(response *http.Response) error {
	requestID := response.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = response.Header.Get("X-Ya-Request-Id")
	}
	if requestID != "" {
		return fmt.Errorf("Lockbox returned HTTP %d (request ID %s)", response.StatusCode, requestID)
	}
	return fmt.Errorf("Lockbox returned HTTP %d", response.StatusCode)
}
