package webhook

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Yniphe/ycr-credential-provider/internal/lockbox"
)

type fakeGetter struct {
	secretID string
	property string
	value    lockbox.Value
	err      error
}

func (g *fakeGetter) GetProperty(_ context.Context, secretID, property string) (lockbox.Value, error) {
	g.secretID = secretID
	g.property = property
	return g.value, g.err
}

func TestHandlerReturnsProperty(t *testing.T) {
	t.Parallel()
	getter := &fakeGetter{value: lockbox.Value{Text: "secret-value", VersionID: "version-1"}}
	handler, err := New(getter, []string{"e6qallowed"})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/secrets/e6qallowed?property=ACCESS_SECRET_KEY", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if getter.secretID != "e6qallowed" || getter.property != "ACCESS_SECRET_KEY" {
		t.Fatalf("unexpected lookup: %q %q", getter.secretID, getter.property)
	}
	if !strings.Contains(response.Body.String(), "secret-value") || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected response: headers=%v body=%s", response.Header(), response.Body.String())
	}
}

func TestHandlerRejectsSecretOutsideAllowlist(t *testing.T) {
	t.Parallel()
	handler, err := New(&fakeGetter{}, []string{"e6qallowed"})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/secrets/e6qother?property=password", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestNewRejectsInvalidSecretID(t *testing.T) {
	t.Parallel()
	_, err := New(&fakeGetter{}, []string{"../../not-a-secret-id"})
	if err == nil {
		t.Fatal("expected invalid allowlist error")
	}
}

func TestHandlerHidesBackendError(t *testing.T) {
	t.Parallel()
	handler, err := New(&fakeGetter{err: errors.New("sensitive upstream detail")}, []string{"e6qallowed"})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/secrets/e6qallowed?property=password", nil))
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "sensitive") {
		t.Fatalf("unsafe response: status=%d body=%s", response.Code, response.Body.String())
	}
}
