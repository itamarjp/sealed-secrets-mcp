package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadiness(t *testing.T) {
	_, cert := testKey(t)
	type scenario struct {
		name       string
		apiStatus  int
		apiBody    string
		certStatus int
		certBody   []byte
		want       int
	}
	cases := []scenario{
		{"healthy", 200, `{"gitVersion":"v1.37.0"}`, 200, cert, 200},
		{"api unavailable", 503, "", 200, cert, 503},
		{"api malformed", 200, `{}`, 200, cert, 503},
		{"controller unavailable", 200, `{"gitVersion":"v1.37.0"}`, 503, nil, 503},
		{"invalid certificate", 200, `{"gitVersion":"v1.37.0"}`, 200, []byte("not a certificate"), 503},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.apiStatus)
				_, _ = w.Write([]byte(tc.apiBody))
			})
			mux.HandleFunc("/v1/cert.pem", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.certStatus)
				_, _ = w.Write(tc.certBody)
			})
			deps := httptest.NewServer(mux)
			defer deps.Close()
			k, err := newKube(deps.URL)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			rec := httptest.NewRecorder()
			readinessHandler(k, deps.URL+"/v1/cert.pem").ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
			if tc.want == 503 && rec.Body.String() != "not ready\n" {
				t.Errorf("unexpected error response: %q", rec.Body.String())
			}
		})
	}
}

func TestReadinessCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	k, err := newKube("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if err := k.checkAPIReachable(ctx); err == nil {
		t.Fatal("expected cancelled request to fail")
	}
}
