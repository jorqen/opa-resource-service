package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jorqen/opa-resource-service/internal/authz"
	"github.com/jorqen/opa-resource-service/internal/server"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	policyPath := flag.String("policy", "policy/authz.rego", "path to the Rego policy file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

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
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.Info("listening", "addr", *addr, "policy", *policyPath)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	logger.Info("stopped")
	return nil
}
