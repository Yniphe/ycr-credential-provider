package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Yniphe/ycr-credential-provider/internal/provider"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const maxRequestSize = 1 << 20

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "ycr-credential-provider: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ycr-credential-provider", flag.ContinueOnError)
	flags.SetOutput(stderr)

	serviceAccountID := flags.String("service-account-id", env("YC_SERVICE_ACCOUNT_ID", ""), "Yandex Cloud service account ID; defaults to the Kubernetes ServiceAccount annotation")
	annotationKey := flags.String("service-account-annotation", env("YC_SERVICE_ACCOUNT_ANNOTATION", provider.DefaultServiceAccountAnnotation), "Kubernetes ServiceAccount annotation containing the Yandex Cloud service account ID")
	registryHost := flags.String("registry-host", env("YCR_REGISTRY_HOST", provider.DefaultRegistryHost), "Yandex Container Registry hostname")
	tokenURL := flags.String("token-url", env("YC_TOKEN_URL", provider.DefaultTokenURL), "Yandex Cloud workload identity token exchange endpoint")
	timeout := flags.Duration("timeout", 10*time.Second, "token exchange timeout")
	safetyMargin := flags.Duration("cache-safety-margin", 5*time.Minute, "time subtracted from the IAM token lifetime")
	showVersion := flags.Bool("version", false, "print version information")

	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *showVersion {
		_, err := fmt.Fprintf(stdout, "ycr-credential-provider %s (commit %s, built %s)\n", version, commit, date)
		return err
	}

	cfg := provider.Config{
		TokenURL:                 *tokenURL,
		RegistryHost:             *registryHost,
		ServiceAccountID:         *serviceAccountID,
		ServiceAccountAnnotation: *annotationKey,
		Timeout:                  *timeout,
		CacheSafetyMargin:        *safetyMargin,
		UserAgent:                "ycr-credential-provider/" + version,
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	requestBytes, err := io.ReadAll(io.LimitReader(stdin, maxRequestSize+1))
	if err != nil {
		return fmt.Errorf("read credential request: %w", err)
	}
	if len(requestBytes) > maxRequestSize {
		return fmt.Errorf("credential request exceeds %d bytes", maxRequestSize)
	}

	var request provider.CredentialProviderRequest
	decoder := json.NewDecoder(strings.NewReader(string(requestBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("decode credential request: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return err
	}

	httpClient := &http.Client{
		Timeout: *timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	client := provider.New(cfg, httpClient)
	response, err := client.Provide(context.Background(), request)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(response); err != nil {
		return fmt.Errorf("encode credential response: %w", err)
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return errors.New("credential request contains multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode trailing credential request data: %w", err)
	}
	return nil
}

func env(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}
