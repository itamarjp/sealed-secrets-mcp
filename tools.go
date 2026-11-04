package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type tools struct {
	kube           *kube
	certURL        string
	allowedTarget  *target
	allowedTargets []target
	rotateTargets  []target
	hybrid         bool
}

type target struct {
	Namespace string `json:"namespace" jsonschema:"namespace of the Secret"`
	Name      string `json:"name" jsonschema:"name of the Secret"`
}

func (t target) validate() error {
	if !validName(t.Namespace) || !validName(t.Name) {
		return errors.New("namespace and name must be valid Kubernetes names")
	}
	return nil
}

type sealedOutput struct {
	SealedSecret *sealedSecret `json:"sealedSecret" jsonschema:"the SealedSecret resource; commit it unchanged (as YAML or JSON) and copy encryptedData values exactly"`
	File         string        `json:"file" jsonschema:"conventional file name"`
	Notes        []string      `json:"notes,omitempty" jsonschema:"actions required before or after committing"`
}

type keySpec struct {
	Key      string `json:"key" jsonschema:"data key, e.g. PASSWORD"`
	Length   int    `json:"length,omitempty" jsonschema:"random bytes for hex/base64, characters for alnum; default 32"`
	Encoding string `json:"encoding,omitempty" jsonschema:"hex (default), base64 (standard, padded), base64url or alnum"`
}

type generateInput struct {
	target
	Type string    `json:"type,omitempty" jsonschema:"Secret type; default Opaque"`
	Keys []keySpec `json:"keys" jsonschema:"keys to fill with random values"`
}

// Rotation preserves the exact namespace/name and all unmodified keys.
// It only returns encrypted output; the cluster remains unchanged.
type rotateInput struct {
	target
	Keys []keySpec `json:"keys" jsonschema:"existing keys to replace with random values"`
}

func scoped(ctx context.Context, scope string) bool {
	info := auth.TokenInfoFromContext(ctx)
	if info == nil {
		return false
	}
	for _, s := range info.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (t *tools) rotateAllowed(in target) bool {
	for _, allowed := range t.rotateTargets {
		if allowed == in {
			return true
		}
	}
	return false
}

func (t *tools) register(s *mcp.Server, allowGenerate bool) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "seal_existing_secret",
		Description: "Read a Secret that already exists in the cluster and return it as a strict-scope " +
			"SealedSecret manifest with the same values. Use this to move a manually created Secret into Git " +
			"without rotating it. Only ciphertext is returned.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, t.sealExisting)
	if len(t.rotateTargets) > 0 {
		mcp.AddTool(s, &mcp.Tool{
			Name:        "rotate_sealed_secret",
			Description: "Generate new random values for named keys of an existing exact-target Secret and return only a strict-scope SealedSecret. Requires OAuth seal:rotate scope and explicit per-Secret rotation allowlist. Does not write to Kubernetes; commit and reconcile via reviewed GitOps before updating workloads.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		}, t.rotate)
	}
	if allowGenerate {
		mcp.AddTool(s, &mcp.Tool{
			Name: "generate_sealed_secret",
			Description: "Create a new credential: generate random values server-side and return them only as a " +
				"strict-scope SealedSecret resource (JSON). Refuses if the Secret already exists in the cluster, so an " +
				"existing credential is never rotated by accident. Nothing is written to the cluster.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		}, t.generate)
	}
}

func (t *tools) targetAllowed(in target) bool {
	if t.allowedTarget != nil && *t.allowedTarget == in {
		return true
	}
	for _, permitted := range t.allowedTargets {
		if permitted == in {
			return true
		}
	}
	return false
}

func (t *tools) sealExisting(ctx context.Context, _ *mcp.CallToolRequest, in target) (_ *mcp.CallToolResult, _ sealedOutput, err error) {
	defer func() { log(ctx, "seal_existing_secret", in, err) }()
	if err = in.validate(); err != nil {
		return nil, sealedOutput{}, err
	}
	if t.hybrid {
		identity := clientFrom(ctx)
		if strings.HasPrefix(identity, "pocketid:") && !scoped(ctx, pocketScope) {
			return nil, sealedOutput{}, errors.New("seal:existing scope is required")
		}
		if strings.HasPrefix(identity, "pocketid:") {
			if !t.targetAllowed(in) {
				return nil, sealedOutput{}, errors.New("target is not permitted for this OAuth identity")
			}
		} else if !strings.HasPrefix(identity, "jwt:") {
			return nil, sealedOutput{}, errors.New("unauthorized client identity")
		}
	} else if (t.allowedTarget != nil || len(t.allowedTargets) > 0) && !t.targetAllowed(in) {
		return nil, sealedOutput{}, errors.New("target is not permitted for this OAuth identity")
	} else if t.allowedTarget != nil || len(t.allowedTargets) > 0 {
		if clientFrom(ctx) != "unknown" && !scoped(ctx, pocketScope) {
			return nil, sealedOutput{}, errors.New("seal:existing scope is required")
		}
	}
	live, err := t.kube.getSecret(ctx, in.Namespace, in.Name)
	if errors.Is(err, errNotFound) {
		return nil, sealedOutput{}, fmt.Errorf("secret %s/%s does not exist; use generate_sealed_secret", in.Namespace, in.Name)
	}
	if err != nil {
		return nil, sealedOutput{}, err
	}
	if live.Type == "kubernetes.io/service-account-token" {
		return nil, sealedOutput{}, errors.New("service account tokens are generated by Kubernetes and must not be sealed")
	}

	var notes []string
	adopted := live.Metadata.Annotations["sealedsecrets.bitnami.com/managed"] == "true"
	for _, o := range live.Metadata.OwnerReferences {
		if o.Kind == "SealedSecret" {
			adopted = true
			notes = append(notes, "already owned by SealedSecret "+o.Name+"; this manifest replaces it")
		} else {
			notes = append(notes, fmt.Sprintf("owned by %s %s, which may regenerate it; check that it belongs in Git", o.Kind, o.Name))
		}
	}
	if !adopted {
		notes = append(notes, fmt.Sprintf("the controller will not overwrite an unmanaged Secret; before the first sync run: "+
			"kubectl -n %s annotate secret %s sealedsecrets.bitnami.com/managed=true", in.Namespace, in.Name))
	}

	out, err := t.seal(ctx, secretSpec{
		Namespace: in.Namespace, Name: in.Name, Type: live.Type,
		Labels: live.Metadata.Labels, Annotations: cleanAnnotations(live.Metadata.Annotations),
		Data: live.Data,
	})
	out.Notes = append(out.Notes, notes...)
	return nil, out, err
}

func (t *tools) generate(ctx context.Context, _ *mcp.CallToolRequest, in generateInput) (_ *mcp.CallToolResult, _ sealedOutput, err error) {
	defer func() { log(ctx, "generate_sealed_secret", in.target, err) }()
	if t.hybrid && !strings.HasPrefix(clientFrom(ctx), "jwt:") {
		return nil, sealedOutput{}, errors.New("credential generation is not permitted for OAuth clients")
	}
	if err = in.validate(); err != nil {
		return nil, sealedOutput{}, err
	}
	if len(in.Keys) == 0 {
		return nil, sealedOutput{}, errors.New("at least one key is required")
	}
	switch _, err := t.kube.getSecret(ctx, in.Namespace, in.Name); {
	case err == nil:
		return nil, sealedOutput{}, fmt.Errorf("secret %s/%s already exists; reuse it with seal_existing_secret instead of rotating", in.Namespace, in.Name)
	case !errors.Is(err, errNotFound):
		return nil, sealedOutput{}, fmt.Errorf("cannot confirm the Secret is new: %w", err)
	}

	data := make(map[string][]byte, len(in.Keys))
	for _, k := range in.Keys {
		if !secretKey.MatchString(k.Key) || data[k.Key] != nil {
			return nil, sealedOutput{}, fmt.Errorf("invalid or duplicate key %q", k.Key)
		}
		v, err := randomValue(k)
		if err != nil {
			return nil, sealedOutput{}, err
		}
		data[k.Key] = v
	}
	typ := in.Type
	if typ == "" {
		typ = "Opaque"
	}
	out, err := t.seal(ctx, secretSpec{Namespace: in.Namespace, Name: in.Name, Type: typ, Data: data})
	return nil, out, err
}

// rotate is deliberately restricted to OAuth identities with an explicit
// step-up scope and a per-resource allowlist. Legacy JWTs cannot rotate.
func (t *tools) rotate(ctx context.Context, _ *mcp.CallToolRequest, in rotateInput) (_ *mcp.CallToolResult, _ sealedOutput, err error) {
	defer func() { log(ctx, "rotate_sealed_secret", in.target, err) }()
	if err = in.validate(); err != nil {
		return nil, sealedOutput{}, err
	}
	identity := clientFrom(ctx)
	if identity == "unknown" || (t.hybrid && !strings.HasPrefix(identity, "pocketid:")) || !scoped(ctx, rotateScope) {
		return nil, sealedOutput{}, errors.New("OAuth seal:rotate scope is required")
	}
	if !t.targetAllowed(in.target) || !t.rotateAllowed(in.target) {
		return nil, sealedOutput{}, errors.New("target is not permitted for OAuth rotation")
	}
	if len(in.Keys) == 0 {
		return nil, sealedOutput{}, errors.New("at least one existing key is required")
	}
	live, err := t.kube.getSecret(ctx, in.Namespace, in.Name)
	if err != nil {
		return nil, sealedOutput{}, fmt.Errorf("rotation requires existing Secret: %w", err)
	}
	if live.Type == "kubernetes.io/service-account-token" {
		return nil, sealedOutput{}, errors.New("service account tokens cannot be rotated")
	}
	data := make(map[string][]byte, len(live.Data))
	for key, value := range live.Data {
		data[key] = append([]byte(nil), value...)
	}
	seen := map[string]bool{}
	for _, key := range in.Keys {
		if !secretKey.MatchString(key.Key) || seen[key.Key] {
			return nil, sealedOutput{}, errors.New("invalid or duplicate key")
		}
		seen[key.Key] = true
		if _, exists := data[key.Key]; !exists {
			return nil, sealedOutput{}, errors.New("rotation key does not exist in Secret")
		}
		value, e := randomValue(key)
		if e != nil {
			return nil, sealedOutput{}, e
		}
		data[key.Key] = value
	}
	out, err := t.seal(ctx, secretSpec{
		Namespace: in.Namespace, Name: in.Name, Type: live.Type,
		Labels: live.Metadata.Labels, Annotations: cleanAnnotations(live.Metadata.Annotations), Data: data,
	})
	if err == nil {
		out.Notes = []string{"Rotation is NOT applied to the cluster. Commit this manifest to GitOps, wait for SealedSecret reconciliation, then update application credentials. Existing Secret is unchanged until GitOps applies."}
	}
	return nil, out, err
}

func (t *tools) seal(ctx context.Context, s secretSpec) (sealedOutput, error) {
	pem, err := fetchCert(ctx, t.certURL)
	if err != nil {
		return sealedOutput{}, err
	}
	pub, err := parseCert(pem)
	if err != nil {
		return sealedOutput{}, err
	}
	sealed, err := sealStrict(pub, s)
	if err != nil {
		return sealedOutput{}, err
	}
	return sealedOutput{SealedSecret: sealed, File: s.Name + ".sealed.yaml"}, nil
}

// secretKey is the Kubernetes rule for Secret data keys.
var secretKey = regexp.MustCompile(`^[-._a-zA-Z0-9]{1,253}$`)

func randomValue(k keySpec) ([]byte, error) {
	n := k.Length
	if n == 0 {
		n = 32
	}
	if n < 16 || n > 256 {
		return nil, fmt.Errorf("key %q: length must be between 16 and 256", k.Key)
	}
	switch k.Encoding {
	case "", "hex", "base64", "base64url":
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		switch k.Encoding {
		case "base64":
			// Standard, padded alphabet (RFC 4648 section 4), as Go's
			// base64.StdEncoding.Strict() and openssl rand -base64 expect.
			return []byte(base64.StdEncoding.EncodeToString(b)), nil
		case "base64url":
			return []byte(base64.RawURLEncoding.EncodeToString(b)), nil
		}
		return []byte(hex.EncodeToString(b)), nil
	case "alnum":
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		b := make([]byte, n)
		for i := range b {
			j, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				return nil, err
			}
			b[i] = alphabet[j.Int64()]
		}
		return b, nil
	}
	return nil, fmt.Errorf("key %q: unknown encoding %q", k.Key, k.Encoding)
}

// cleanAnnotations drops annotations that describe the live object rather
// than the desired Secret.
func cleanAnnotations(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		if k == "kubectl.kubernetes.io/last-applied-configuration" || strings.HasPrefix(k, "sealedsecrets.bitnami.com/") {
			continue
		}
		out[k] = v
	}
	return out
}

// log writes an audit line. It never includes Secret values.
func log(ctx context.Context, tool string, t target, err error) {
	attrs := []any{"client", clientFrom(ctx), "tool", tool, "namespace", t.Namespace, "name", t.Name}
	if err != nil {
		slog.WarnContext(ctx, "tool failed", append(attrs, "error", err)...)
		return
	}
	slog.InfoContext(ctx, "sealed", attrs...)
}
