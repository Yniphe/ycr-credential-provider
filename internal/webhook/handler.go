package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"unicode"

	"github.com/Yniphe/ycr-credential-provider/internal/lockbox"
)

type Getter interface {
	GetProperty(context.Context, string, string) (lockbox.Value, error)
}

type Handler struct {
	getter  Getter
	allowed map[string]struct{}
}

func New(getter Getter, allowedSecretIDs []string) (*Handler, error) {
	if getter == nil {
		return nil, errors.New("Lockbox getter is required")
	}
	allowed := make(map[string]struct{}, len(allowedSecretIDs))
	for _, id := range allowedSecretIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if err := lockbox.ValidateSecretID(id); err != nil {
			return nil, err
		}
		allowed[id] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil, errors.New("at least one allowed Lockbox secret ID is required")
	}
	return &Handler{getter: getter, allowed: allowed}, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'")
	writer.Header().Set("X-Content-Type-Options", "nosniff")

	switch request.URL.Path {
	case "/healthz", "/readyz":
		if request.Method != http.MethodGet {
			methodNotAllowed(writer)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	const prefix = "/v1/secrets/"
	if !strings.HasPrefix(request.URL.Path, prefix) {
		writeError(writer, http.StatusNotFound, "not found")
		return
	}
	secretID := strings.TrimPrefix(request.URL.Path, prefix)
	if secretID == "" || strings.Contains(secretID, "/") {
		writeError(writer, http.StatusBadRequest, "invalid secret ID")
		return
	}
	if _, ok := h.allowed[secretID]; !ok {
		writeError(writer, http.StatusForbidden, "secret is not allowed")
		return
	}
	property := request.URL.Query().Get("property")
	if err := validateIdentifier(property, 256, "property"); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}

	value, err := h.getter.GetProperty(request.Context(), secretID, property)
	if err != nil {
		switch {
		case errors.Is(err, lockbox.ErrSecretNotFound), errors.Is(err, lockbox.ErrPropertyNotFound):
			writeError(writer, http.StatusNotFound, "secret or property not found")
		default:
			writeError(writer, http.StatusBadGateway, "Lockbox request failed")
		}
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{
		"value":     value.Text,
		"versionId": value.VersionID,
	})
}

func validateIdentifier(value string, maxLength int, name string) error {
	if value == "" {
		return errors.New(name + " is required")
	}
	if len(value) > maxLength {
		return errors.New(name + " is too long")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return errors.New(name + " contains control characters")
		}
	}
	return nil
}

func methodNotAllowed(writer http.ResponseWriter) {
	writer.Header().Set("Allow", http.MethodGet)
	writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{"error": message})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
