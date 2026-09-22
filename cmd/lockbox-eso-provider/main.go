package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Yniphe/ycr-credential-provider/internal/identity"
	"github.com/Yniphe/ycr-credential-provider/internal/lockbox"
	"github.com/Yniphe/ycr-credential-provider/internal/webhook"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type config struct {
	listenAddress     string
	tokenURL          string
	lockboxAPIURL     string
	serviceAccountID  string
	serviceAccountJWT string
	allowedSecretIDs  []string
	timeout           time.Duration
	cacheSafetyMargin time.Duration
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "lockbox-eso-provider: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	cfg, showVersion, err := parseConfig(args, stderr)
	if err != nil {
		return err
	}
	if showVersion {
		_, err := fmt.Fprintf(stdout, "lockbox-eso-provider %s (commit %s, built %s)\n", version, commit, date)
		return err
	}

	httpClient := &http.Client{
		Timeout: cfg.timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	identityConfig := identity.Config{
		TokenURL:  cfg.tokenURL,
		Timeout:   cfg.timeout,
		UserAgent: "lockbox-eso-provider/" + version,
	}
	if err := identityConfig.Validate(); err != nil {
		return err
	}
	identityClient := identity.New(identityConfig, httpClient)
	tokenSource, err := identity.NewFileExchangeSource(identityClient, cfg.serviceAccountID, cfg.serviceAccountJWT, cfg.cacheSafetyMargin)
	if err != nil {
		return err
	}
	lockboxClient, err := lockbox.New(lockbox.Config{
		APIURL:    cfg.lockboxAPIURL,
		Timeout:   cfg.timeout,
		UserAgent: "lockbox-eso-provider/" + version,
	}, httpClient, tokenSource)
	if err != nil {
		return err
	}
	handler, err := webhook.New(lockboxClient, cfg.allowedSecretIDs)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              cfg.listenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shut down HTTP server: %w", err)
		}
		return nil
	case err := <-serverErrors:
		if err == http.ErrServerClosed {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	}
}

func parseConfig(args []string, stderr io.Writer) (config, bool, error) {
	flags := flag.NewFlagSet("lockbox-eso-provider", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listenAddress := flags.String("listen-address", env("LISTEN_ADDRESS", "127.0.0.1:8081"), "HTTP listen address; keep loopback when deployed as an ESO sidecar")
	tokenURL := flags.String("token-url", env("YC_TOKEN_URL", identity.DefaultTokenURL), "Yandex Cloud workload identity token exchange endpoint")
	lockboxAPIURL := flags.String("lockbox-api-url", env("YC_LOCKBOX_API_URL", lockbox.DefaultAPIURL), "Yandex Lockbox payload API endpoint")
	serviceAccountID := flags.String("service-account-id", env("YC_SERVICE_ACCOUNT_ID", ""), "Yandex Cloud service account ID linked to the workload identity federation")
	serviceAccountJWT := flags.String("service-account-token-file", env("YC_SERVICE_ACCOUNT_TOKEN_FILE", "/var/run/secrets/yandex.cloud/token"), "projected Kubernetes ServiceAccount token file")
	allowedSecretIDs := flags.String("allowed-secret-ids", env("LOCKBOX_ALLOWED_SECRET_IDS", ""), "comma-separated allowlist of Lockbox secret IDs")
	timeout := flags.Duration("timeout", 10*time.Second, "Yandex API request timeout")
	cacheSafetyMargin := flags.Duration("cache-safety-margin", 5*time.Minute, "time subtracted from the IAM token lifetime")
	showVersion := flags.Bool("version", false, "print version information")
	if err := flags.Parse(args); err != nil {
		return config{}, false, err
	}
	if flags.NArg() != 0 {
		return config{}, false, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *showVersion {
		return config{}, true, nil
	}

	cfg := config{
		listenAddress:     strings.TrimSpace(*listenAddress),
		tokenURL:          strings.TrimSpace(*tokenURL),
		lockboxAPIURL:     strings.TrimSpace(*lockboxAPIURL),
		serviceAccountID:  strings.TrimSpace(*serviceAccountID),
		serviceAccountJWT: strings.TrimSpace(*serviceAccountJWT),
		allowedSecretIDs:  splitList(*allowedSecretIDs),
		timeout:           *timeout,
		cacheSafetyMargin: *cacheSafetyMargin,
	}
	if cfg.listenAddress == "" {
		return config{}, false, fmt.Errorf("listen address is required")
	}
	if len(cfg.allowedSecretIDs) == 0 {
		return config{}, false, fmt.Errorf("at least one allowed Lockbox secret ID is required")
	}
	return cfg, false, nil
}

func splitList(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func env(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}
