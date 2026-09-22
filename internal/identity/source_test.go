package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestFileExchangeSourceCachesAndRefreshes(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		json.NewEncoder(writer).Encode(map[string]any{
			"access_token": "iam-token-" + string(rune('0'+call)),
			"token_type":   "Bearer",
			"expires_in":   120,
		})
	}))
	t.Cleanup(server.Close)

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("subject-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := New(Config{TokenURL: server.URL, Timeout: time.Second}, server.Client())
	source, err := NewFileExchangeSource(client, "ajeserviceaccount", tokenFile, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	source.now = func() time.Time { return now }

	first, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first != second || calls.Load() != 1 {
		t.Fatalf("token was not cached: first=%q second=%q calls=%d", first, second, calls.Load())
	}

	now = now.Add(61 * time.Second)
	third, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if third == first || calls.Load() != 2 {
		t.Fatalf("token was not refreshed: first=%q third=%q calls=%d", first, third, calls.Load())
	}
}
