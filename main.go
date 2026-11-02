// Command sealed-secrets-mcp is an MCP server that turns Kubernetes Secrets
// into Sealed Secrets manifests without ever returning plaintext.
//
//	sealed-secrets-mcp serve
//	sealed-secrets-mcp token --client codex --ttl 24h
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve()
	case "token":
		err = token(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sealed-secrets-mcp serve | token --client NAME [--ttl 24h] | version")
	os.Exit(2)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func newSigner() (*signer, error) {
	maxTTL, err := time.ParseDuration(env("SEAL_MAX_TTL", "24h"))
	if err != nil {
		return nil, fmt.Errorf("SEAL_MAX_TTL: %w", err)
	}
	return loadSigner(env("SEAL_SIGNING_KEY_FILE", "/etc/sealed-secrets-mcp/signing-key"), os.Getenv("SEAL_AUDIENCE"), maxTTL)
}

func token(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	client := fs.String("client", "", "name of the client the token is for, e.g. codex")
	ttl := fs.Duration("ttl", 24*time.Hour, "token lifetime")
	_ = fs.Parse(args)
	s, err := newSigner()
	if err != nil {
		return err
	}
	tok, err := s.issue(*client, *ttl)
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func serve() error {
	mode := env("SEAL_AUTH_MODE", "jwt")
	var verify func(context.Context, string, *http.Request) (*auth.TokenInfo, error)
	var pocket *pocketVerifier
	switch mode {
	case "jwt":
		s, err := newSigner()
		if err != nil {
			return err
		}
		verify = s.verify
	case "pocketid", "hybrid":
		var err error
		pocket, err = newPocketVerifier(os.Getenv("SEAL_POCKET_ID_ISSUER"), os.Getenv("SEAL_AUDIENCE"), os.Getenv("SEAL_POCKET_ID_SUB"))
		if err != nil {
			return err
		}
		if mode == "hybrid" {
			legacy, err := newSigner()
			if err != nil {
				return err
			}
			verify = (&hybridVerifier{legacy: legacy, pocket: pocket}).verify
		} else {
			verify = pocket.verify
		}
	default:
		return fmt.Errorf("unknown SEAL_AUTH_MODE %q", mode)
	}
	k, err := newKube(os.Getenv("SEAL_KUBE_API"))
	if err != nil {
		return err
	}
	t := &tools{kube: k, certURL: env("SEAL_CERT_URL",
		"http://sealed-secrets-controller.kube-system.svc:8080/v1/cert.pem")}
	if pocket != nil {
		// A comma-separated list permits only individually named Secrets.
		// Retain SEAL_POCKET_ID_TARGET_NAME for existing single-target deployments.
		ns := os.Getenv("SEAL_POCKET_ID_TARGET_NAMESPACE")
		names := os.Getenv("SEAL_POCKET_ID_TARGET_NAMES")
		if names == "" {
			names = os.Getenv("SEAL_POCKET_ID_TARGET_NAME")
		}
		seen := make(map[string]bool)
		for _, part := range strings.Split(names, ",") {
			name := strings.TrimSpace(part)
			allowed := target{Namespace: ns, Name: name}
			if err := allowed.validate(); err != nil {
				return fmt.Errorf("invalid Pocket ID target %q: %w", name, err)
			}
			if seen[name] {
				return fmt.Errorf("duplicate Pocket ID target %q", name)
			}
			seen[name] = true
			t.allowedTargets = append(t.allowedTargets, allowed)
		}
		// Rotation is independent of the read allowlist. Empty means denied.
		// Each exact name must already be a permitted OAuth read target.
		rotateNames := os.Getenv("SEAL_POCKET_ID_ROTATE_TARGET_NAMES")
		rotateSeen := make(map[string]bool)
		if rotateNames != "" {
			for _, part := range strings.Split(rotateNames, ",") {
				name := strings.TrimSpace(part)
				allowed := target{Namespace: ns, Name: name}
				if err := allowed.validate(); err != nil {
					return fmt.Errorf("invalid OAuth rotation target %q: %w", name, err)
				}
				if !t.targetAllowed(allowed) || rotateSeen[name] {
					return fmt.Errorf("OAuth rotation target %q must be a unique read-allowed target", name)
				}
				rotateSeen[name] = true
				t.rotateTargets = append(t.rotateTargets, allowed)
			}
		}
		t.hybrid = mode == "hybrid"
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "sealed-secrets-mcp", Version: version}, nil)
	t.register(server, mode != "pocketid")

	mux := http.NewServeMux()
	resource := os.Getenv("SEAL_AUDIENCE")
	if pocket != nil {
		metadata := protectedResourceHandler(resource, pocket.issuer, len(t.rotateTargets) > 0)
		mux.Handle("/.well-known/oauth-protected-resource", metadata)
		mux.Handle("/.well-known/oauth-protected-resource/mcp", metadata)
	}
	var bearerOptions *auth.RequireBearerTokenOptions
	if pocket != nil {
		resourceURL, err := url.Parse(resource)
		if err != nil {
			return err
		}
		bearerOptions = &auth.RequireBearerTokenOptions{
			ResourceMetadataURL: resourceURL.Scheme + "://" + resourceURL.Host + "/.well-known/oauth-protected-resource" + resourceURL.EscapedPath(),
		}
	}
	var mcpHandler http.Handler = auth.RequireBearerToken(verify, bearerOptions)(
		mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
			&mcp.StreamableHTTPOptions{Stateless: true}))
	if bearerOptions != nil {
		scope, err := challengeScope(len(t.rotateTargets) > 0, os.Getenv("SEAL_POCKET_ID_CHALLENGE_ROTATE"))
		if err != nil {
			return err
		}
		mcpHandler = oauthChallenge(bearerOptions.ResourceMetadataURL, scope)(mcpHandler)
	}
	mux.Handle("/mcp", mcpHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("/readyz", readinessHandler(k, t.certURL))

	srv := &http.Server{
		Addr:              env("SEAL_LISTEN", ":8080"),
		Handler:           http.MaxBytesHandler(mux, 1<<20),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	slog.Info("listening", "addr", srv.Addr, "version", version)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
