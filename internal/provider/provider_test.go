package provider

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

func TestProvideExchangesTokenAndReturnsRegistryCredentials(t *testing.T) {
	t.Parallel()

	const (
		ksaToken = "kubernetes-service-account-token"
		ycToken  = "yandex-iam-token"
		ycSAID   = "aje1234567890example"
	)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", request.Method)
		}
		if got := request.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Fatalf("content type = %q", got)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, form, "grant_type", grantType)
		assertFormValue(t, form, "requested_token_type", requestedType)
		assertFormValue(t, form, "audience", ycSAID)
		assertFormValue(t, form, "subject_token", ksaToken)
		assertFormValue(t, form, "subject_token_type", subjectTokenType)

		writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(writer).Encode(map[string]any{
			"access_token": ycToken,
			"token_type":   "Bearer",
			"expires_in":   43200,
		})
	}))
	t.Cleanup(server.Close)

	client := New(Config{
		TokenURL:                 server.URL,
		RegistryHost:             DefaultRegistryHost,
		ServiceAccountAnnotation: DefaultServiceAccountAnnotation,
		Timeout:                  time.Second,
		CacheSafetyMargin:        5 * time.Minute,
	}, server.Client())

	response, err := client.Provide(context.Background(), CredentialProviderRequest{
		APIVersion:          APIVersion,
		Kind:                "CredentialProviderRequest",
		Image:               "cr.yandex/crp123/website@sha256:abcdef",
		ServiceAccountToken: ksaToken,
		ServiceAccountAnnotations: map[string]string{
			DefaultServiceAccountAnnotation: ycSAID,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.CacheKeyType != "Registry" {
		t.Fatalf("cache key type = %q", response.CacheKeyType)
	}
	if response.CacheDuration != "11h55m0s" {
		t.Fatalf("cache duration = %q", response.CacheDuration)
	}
	auth := response.Auth[DefaultRegistryHost]
	if auth.Username != "iam" || auth.Password != ycToken {
		t.Fatalf("unexpected auth response: %#v", auth)
	}
}

func TestProvideUsesConfiguredServiceAccountID(t *testing.T) {
	t.Parallel()

	const configuredID = "ajeconfigured"
	server := tokenServer(t, func(form url.Values) {
		assertFormValue(t, form, "audience", configuredID)
	})

	client := New(Config{
		TokenURL:                 server.URL,
		RegistryHost:             DefaultRegistryHost,
		ServiceAccountID:         configuredID,
		ServiceAccountAnnotation: DefaultServiceAccountAnnotation,
		Timeout:                  time.Second,
		CacheSafetyMargin:        0,
	}, server.Client())

	_, err := client.Provide(context.Background(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
}

func TestProvideRejectsMissingServiceAccountToken(t *testing.T) {
	t.Parallel()
	client := New(testConfig("https://auth.example.test/token"), http.DefaultClient)
	request := validRequest()
	request.ServiceAccountToken = ""

	_, err := client.Provide(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "service account token is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProvideRejectsAnotherRegistry(t *testing.T) {
	t.Parallel()
	client := New(testConfig("https://auth.example.test/token"), http.DefaultClient)
	request := validRequest()
	request.Image = "docker.io/library/alpine:latest"

	_, err := client.Provide(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "is not configured registry") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProvideDoesNotExposeErrorResponseBody(t *testing.T) {
	t.Parallel()
	const sensitiveValue = "must-not-appear"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Request-Id", "request-123")
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte(`{"error":"` + sensitiveValue + `"}`))
	}))
	t.Cleanup(server.Close)

	client := New(testConfig(server.URL), server.Client())
	_, err := client.Provide(context.Background(), validRequest())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), sensitiveValue) {
		t.Fatalf("error exposed response body: %v", err)
	}
	if !strings.Contains(err.Error(), "request-123") {
		t.Fatalf("error does not contain request ID: %v", err)
	}
}

func TestConfigRequiresHTTPS(t *testing.T) {
	t.Parallel()
	config := testConfig("http://auth.yandex.cloud/oauth/token")
	if err := config.Validate(); err == nil {
		t.Fatal("expected insecure token URL to be rejected")
	}
}

func tokenServer(t *testing.T, check func(url.Values)) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatal(err)
		}
		check(form)
		writer.Header().Set("Content-Type", "application/json")
		writer.Write([]byte(`{"access_token":"token","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(server.Close)
	return server
}

func validRequest() CredentialProviderRequest {
	return CredentialProviderRequest{
		APIVersion:          APIVersion,
		Kind:                "CredentialProviderRequest",
		Image:               "cr.yandex/registry/application:latest",
		ServiceAccountToken: "ksa-token",
		ServiceAccountAnnotations: map[string]string{
			DefaultServiceAccountAnnotation: "ajeserviceaccount",
		},
	}
}

func testConfig(tokenURL string) Config {
	return Config{
		TokenURL:                 tokenURL,
		RegistryHost:             DefaultRegistryHost,
		ServiceAccountAnnotation: DefaultServiceAccountAnnotation,
		Timeout:                  time.Second,
		CacheSafetyMargin:        time.Minute,
	}
}

func assertFormValue(t *testing.T, form url.Values, key, expected string) {
	t.Helper()
	if got := form.Get(key); got != expected {
		t.Fatalf("form value %s = %q, want %q", key, got, expected)
	}
}
