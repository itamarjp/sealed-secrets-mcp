package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

var errNotFound = errors.New("not found")

// kube is a minimal read-only Kubernetes API client. It only ever issues
// GET requests for single, named Secrets.
type kube struct {
	base      string // API server URL
	tokenFile string // empty when talking to `kubectl proxy`
	http      *http.Client
}

// newKube returns an in-cluster client, or a client for apiURL (for example
// `kubectl proxy` at http://127.0.0.1:8001) when apiURL is set.
func newKube(apiURL string) (*kube, error) {
	if apiURL != "" {
		return &kube{base: strings.TrimRight(apiURL, "/"), http: &http.Client{Timeout: 10 * time.Second}}, nil
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("not running in a cluster (set SEAL_KUBE_API for local use): %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid service account CA bundle")
	}
	return &kube{
		base:      "https://kubernetes.default.svc",
		tokenFile: saDir + "/token",
		http: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

type liveSecret struct {
	Metadata struct {
		Labels          map[string]string `json:"labels"`
		Annotations     map[string]string `json:"annotations"`
		OwnerReferences []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Type string            `json:"type"`
	Data map[string][]byte `json:"data"` // encoding/json decodes base64 into []byte
}

// getSecret fetches one Secret. It returns errNotFound for a 404 and a
// descriptive error for a 403 so callers can explain missing RBAC.
func (k *kube) getSecret(ctx context.Context, namespace, name string) (*liveSecret, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", k.base, namespace, name), nil)
	if err != nil {
		return nil, err
	}
	if k.tokenFile != "" {
		// Re-read on every call: projected service account tokens rotate.
		tok, err := os.ReadFile(k.tokenFile)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	}
	resp, err := k.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var s liveSecret
		if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&s); err != nil {
			return nil, err
		}
		return &s, nil
	case http.StatusNotFound:
		return nil, errNotFound
	case http.StatusForbidden:
		return nil, fmt.Errorf("RBAC does not allow reading secret %s/%s", namespace, name)
	default:
		return nil, fmt.Errorf("kubernetes API returned %s", resp.Status)
	}
}

// fetchCert downloads the controller's public certificate.
func fetchCert(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching controller certificate: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}

var dns1123 = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

func validName(s string) bool { return dns1123.MatchString(s) && !strings.Contains(s, "..") }
