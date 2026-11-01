package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// checkAPIReachable checks a non-sensitive Kubernetes endpoint. It does not
// enumerate Secrets or require additional permissions on Secret resources.
func (k *kube) checkAPIReachable(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.base+"/version", nil)
	if err != nil {
		return err
	}
	if k.tokenFile != "" {
		token, err := os.ReadFile(k.tokenFile)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	}
	resp, err := k.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kubernetes version endpoint: %s", resp.Status)
	}
	// Check that a response really contains a Kubernetes version.
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&v); err != nil {
		return err
	}
	if v.GitVersion == "" {
		return errors.New("kubernetes version endpoint returned no gitVersion")
	}
	return nil
}

func checkControllerCertificate(ctx context.Context, certURL string) error {
	data, err := fetchCert(ctx, certURL)
	if err != nil {
		return err
	}
	if _, err := parseCert(data); err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return errors.New("controller certificate is outside its validity period")
	}
	return nil
}

// readinessHandler checks dependencies on each probe; no cached success can
// conceal an unavailable API or controller certificate.
func readinessHandler(k *kube, certURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		if err := k.checkAPIReachable(ctx); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		if err := checkControllerCertificate(ctx, certURL); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}
