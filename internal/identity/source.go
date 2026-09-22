package identity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const maxSubjectTokenSize = 1 << 20

type TokenSource interface {
	Token(context.Context) (string, error)
}

type FileExchangeSource struct {
	client           *Client
	serviceAccountID string
	tokenFile        string
	safetyMargin     time.Duration
	now              func() time.Time

	mu        sync.Mutex
	cached    string
	expiresAt time.Time
}

func NewFileExchangeSource(client *Client, serviceAccountID, tokenFile string, safetyMargin time.Duration) (*FileExchangeSource, error) {
	if err := ValidateServiceAccountID(serviceAccountID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(tokenFile) == "" {
		return nil, errors.New("service account token file is required")
	}
	if safetyMargin < 0 {
		return nil, errors.New("cache safety margin must not be negative")
	}
	return &FileExchangeSource{
		client:           client,
		serviceAccountID: serviceAccountID,
		tokenFile:        tokenFile,
		safetyMargin:     safetyMargin,
		now:              time.Now,
	}, nil
}

func (s *FileExchangeSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if s.cached != "" && now.Before(s.expiresAt) {
		return s.cached, nil
	}

	subjectToken, err := readTokenFile(s.tokenFile)
	if err != nil {
		return "", err
	}
	token, err := s.client.Exchange(ctx, s.serviceAccountID, subjectToken)
	if err != nil {
		return "", err
	}

	cacheDuration := token.ExpiresIn
	if cacheDuration > s.safetyMargin {
		cacheDuration -= s.safetyMargin
	} else {
		cacheDuration = 0
	}
	s.cached = token.AccessToken
	s.expiresAt = now.Add(cacheDuration)
	return s.cached, nil
}

func readTokenFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open service account token file: %w", err)
	}
	defer file.Close()

	value, err := io.ReadAll(io.LimitReader(file, maxSubjectTokenSize+1))
	if err != nil {
		return "", fmt.Errorf("read service account token file: %w", err)
	}
	if len(value) > maxSubjectTokenSize {
		return "", errors.New("service account token file is too large")
	}
	token := strings.TrimSpace(string(value))
	if token == "" {
		return "", errors.New("service account token file is empty")
	}
	return token, nil
}
