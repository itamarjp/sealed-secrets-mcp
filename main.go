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
	"os"
	"os/signal"
	"syscall"
	"time"
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

func token(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	client := fs.String("client", "", "name of the client the token is for, e.g. codex")
	ttl := fs.Duration("ttl", 24*time.Hour, "token lifetime")
	_ = fs.Parse(args)
	s, err := signerFromEnv(os.Getenv)
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
	a, err := newApp(os.Getenv)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              env("SEAL_LISTEN", ":8080"),
		Handler:           a.handler,
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
