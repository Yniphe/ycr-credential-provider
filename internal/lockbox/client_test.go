package lockbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type staticTokenSource string

func (s staticTokenSource) Token(context.Context) (string, error) { return string(s), nil }

func TestGetProperty(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/lockbox/v1/secrets/e6qsecret/payload" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer iam-token" {
			t.Fatalf("authorization = %q", got)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Write([]byte(`{"entries":[{"key":"ACCESS_KEY_ID","textValue":"key-id"},{"key":"ACCESS_SECRET_KEY","textValue":"secret-value"}],"versionId":"version-1"}`))
	}))
	t.Cleanup(server.Close)

	client, err := New(Config{APIURL: server.URL, Timeout: time.Second}, server.Client(), staticTokenSource("iam-token"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := client.GetProperty(context.Background(), "e6qsecret", "ACCESS_SECRET_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if value.Text != "secret-value" || value.VersionID != "version-1" {
		t.Fatalf("unexpected value: %#v", value)
	}
}

func TestGetPropertyDoesNotExposeErrorBody(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Request-Id", "request-123")
		writer.WriteHeader(http.StatusForbidden)
		writer.Write([]byte(`{"message":"must-not-appear"}`))
	}))
	t.Cleanup(server.Close)

	client, err := New(Config{APIURL: server.URL, Timeout: time.Second}, server.Client(), staticTokenSource("iam-token"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetProperty(context.Background(), "e6qsecret", "password")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "must-not-appear") || !strings.Contains(err.Error(), "request-123") {
		t.Fatalf("unsafe or incomplete error: %v", err)
	}
}
