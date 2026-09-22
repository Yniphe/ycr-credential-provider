package identity

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestExchange(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatal(err)
		}
		if got := form.Get("audience"); got != "ajeserviceaccount" {
			t.Fatalf("audience = %q", got)
		}
		if got := form.Get("subject_token"); got != "subject-token" {
			t.Fatalf("subject token = %q", got)
		}
		writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(writer).Encode(map[string]any{
			"access_token": "iam-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(server.Close)

	client := New(Config{TokenURL: server.URL, Timeout: time.Second}, server.Client())
	token, err := client.Exchange(context.Background(), "ajeserviceaccount", "subject-token")
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "iam-token" || token.ExpiresIn != time.Hour {
		t.Fatalf("unexpected token: %#v", token)
	}
}

func TestExchangeDoesNotExposeErrorBody(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Request-Id", "request-123")
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte(`{"secret":"must-not-appear"}`))
	}))
	t.Cleanup(server.Close)

	client := New(Config{TokenURL: server.URL, Timeout: time.Second}, server.Client())
	_, err := client.Exchange(context.Background(), "ajeserviceaccount", "subject-token")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "must-not-appear") || !strings.Contains(err.Error(), "request-123") {
		t.Fatalf("unsafe or incomplete error: %v", err)
	}
}
