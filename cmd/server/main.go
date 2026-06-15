package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jorqen/opa-resource-service/internal/authz"
	"github.com/jorqen/opa-resource-service/internal/server"
)

const (
	// readHeaderTimeout bounds how long a client may take to send request
	// headers, guarding against Slowloris-style connection holding.
	readHeaderTimeout = 5 * time.Second
	// shutdownTimeout bounds the graceful drain of in-flight requests before
	// the server is forced to stop.
	shutdownTimeout = 5 * time.Second
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	policyPath := flag.String("policy", "policy/authz.rego", "path to the Rego policy file")
	flag.Parse()

	// Cancel the root context on SIGINT/SIGTERM so the policy watcher and the
	// HTTP server both unwind cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	authorizer, err := authz.NewFromFile(ctx, *policyPath, logger)
	if err != nil {
		return err
	}

	go func() {
		if err := authorizer.WatchFile(ctx, *policyPath); err != nil {
			logger.Error("policy watcher stopped", "error", err)
		}
	}()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           server.New(authorizer, logger),
		ReadHeaderTimeout: readHeaderTimeout,
	}

	// Serve in the background so we can wait for either a startup failure or a
	// shutdown signal, then drain in-flight requests before returning.
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", *addr, "policy", *policyPath)
		serverErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	logger.Info("stopped")
	return nil
}
