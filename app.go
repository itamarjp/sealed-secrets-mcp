package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// app is the fully configured HTTP server, built from environment variables.
// serve only adds the listener and signal handling, so tests can exercise the
// same configuration and routing through newApp.
type app struct {
	handler http.Handler
	tools   *tools
	pocket  *pocketVerifier
}

func newApp(getenv func(string) string) (*app, error) {
	envOr := func(key, def string) string {
		if v := getenv(key); v != "" {
			return v
		}
		return def
	}
	mode := envOr("SEAL_AUTH_MODE", "jwt")
	var verify func(context.Context, string, *http.Request) (*auth.TokenInfo, error)
	var pocket *pocketVerifier
	switch mode {
	case "jwt":
		s, err := signerFromEnv(getenv)
		if err != nil {
			return nil, err
		}
		verify = s.verify
	case "pocketid", "hybrid":
		var err error
		pocket, err = newPocketVerifier(getenv("SEAL_POCKET_ID_ISSUER"), getenv("SEAL_AUDIENCE"), getenv("SEAL_POCKET_ID_SUB"))
		if err != nil {
			return nil, err
		}
		if mode == "hybrid" {
			legacy, err := signerFromEnv(getenv)
			if err != nil {
				return nil, err
			}
			verify = (&hybridVerifier{legacy: legacy, pocket: pocket}).verify
		} else {
			verify = pocket.verify
		}
	default:
		return nil, fmt.Errorf("unknown SEAL_AUTH_MODE %q", mode)
	}
	k, err := newKube(getenv("SEAL_KUBE_API"))
	if err != nil {
		return nil, err
	}
	t := &tools{kube: k, certURL: envOr("SEAL_CERT_URL",
		"http://sealed-secrets-controller.kube-system.svc:8080/v1/cert.pem")}
	if pocket != nil {
		// Retain SEAL_POCKET_ID_TARGET_NAME for existing single-target deployments.
		names := getenv("SEAL_POCKET_ID_TARGET_NAMES")
		if names == "" {
			names = getenv("SEAL_POCKET_ID_TARGET_NAME")
		}
		t.allowedTargets, t.rotateTargets, err = parseTargets(getenv("SEAL_POCKET_ID_TARGET_NAMESPACE"),
			names, getenv("SEAL_POCKET_ID_ROTATE_TARGET_NAMES"))
		if err != nil {
			return nil, err
		}
		t.hybrid = mode == "hybrid"
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "sealed-secrets-mcp", Version: version}, nil)
	t.register(server, mode != "pocketid")

	mux := http.NewServeMux()
	resource := getenv("SEAL_AUDIENCE")
	var bearerOptions *auth.RequireBearerTokenOptions
	if pocket != nil {
		metadata := protectedResourceHandler(resource, pocket.issuer, len(t.rotateTargets) > 0)
		mux.Handle("/.well-known/oauth-protected-resource", metadata)
		mux.Handle("/.well-known/oauth-protected-resource/mcp", metadata)
		resourceURL, err := url.Parse(resource)
		if err != nil {
			return nil, err
		}
		bearerOptions = &auth.RequireBearerTokenOptions{
			ResourceMetadataURL: resourceURL.Scheme + "://" + resourceURL.Host + "/.well-known/oauth-protected-resource" + resourceURL.EscapedPath(),
		}
	}
	var mcpHandler http.Handler = auth.RequireBearerToken(verify, bearerOptions)(
		mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
			&mcp.StreamableHTTPOptions{Stateless: true}))
	if bearerOptions != nil {
		scope, err := challengeScope(len(t.rotateTargets) > 0, getenv("SEAL_POCKET_ID_CHALLENGE_ROTATE"))
		if err != nil {
			return nil, err
		}
		mcpHandler = oauthChallenge(bearerOptions.ResourceMetadataURL, scope)(mcpHandler)
	}
	mux.Handle("/mcp", mcpHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("/readyz", readinessHandler(k, t.certURL))
	return &app{handler: http.MaxBytesHandler(mux, 1<<20), tools: t, pocket: pocket}, nil
}

// parseTargets turns the comma-separated OAuth allowlists into exact targets.
// A comma-separated list permits only individually named Secrets. Rotation is
// independent of the read allowlist: empty means denied, and each exact name
// must already be a permitted OAuth read target.
func parseTargets(namespace, names, rotateNames string) (allowed, rotate []target, err error) {
	seen := make(map[string]bool)
	for _, part := range strings.Split(names, ",") {
		name := strings.TrimSpace(part)
		tg := target{Namespace: namespace, Name: name}
		if err := tg.validate(); err != nil {
			return nil, nil, fmt.Errorf("invalid Pocket ID target %q: %w", name, err)
		}
		if seen[name] {
			return nil, nil, fmt.Errorf("duplicate Pocket ID target %q", name)
		}
		seen[name] = true
		allowed = append(allowed, tg)
	}
	if rotateNames == "" {
		return allowed, nil, nil
	}
	rotateSeen := make(map[string]bool)
	for _, part := range strings.Split(rotateNames, ",") {
		name := strings.TrimSpace(part)
		tg := target{Namespace: namespace, Name: name}
		if err := tg.validate(); err != nil {
			return nil, nil, fmt.Errorf("invalid OAuth rotation target %q: %w", name, err)
		}
		if !seen[name] || rotateSeen[name] {
			return nil, nil, fmt.Errorf("OAuth rotation target %q must be a unique read-allowed target", name)
		}
		rotateSeen[name] = true
		rotate = append(rotate, tg)
	}
	return allowed, rotate, nil
}

func signerFromEnv(getenv func(string) string) (*signer, error) {
	ttl := getenv("SEAL_MAX_TTL")
	if ttl == "" {
		ttl = "24h"
	}
	maxTTL, err := time.ParseDuration(ttl)
	if err != nil {
		return nil, fmt.Errorf("SEAL_MAX_TTL: %w", err)
	}
	keyFile := getenv("SEAL_SIGNING_KEY_FILE")
	if keyFile == "" {
		keyFile = "/etc/sealed-secrets-mcp/signing-key"
	}
	return loadSigner(keyFile, getenv("SEAL_AUDIENCE"), maxTTL)
}
