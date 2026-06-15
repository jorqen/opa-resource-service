// Package server wires the HTTP API together: bearer-token authentication, OPA
// authorization, and the protected resource handler.
package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/jorqen/opa-resource-service/internal/authz"
)

// Authorizer decides whether a request is permitted.
type Authorizer interface {
	Allow(ctx context.Context, in authz.Input) (bool, error)
}

// New returns the HTTP handler for the service.
func New(authorizer Authorizer, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /resource", handleResource)
	return authMiddleware(authorizer, logger, mux)
}

func handleResource(w http.ResponseWriter, r *http.Request) {
	claims, _ := claimsFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "access granted",
		"user":    claims.Username,
	})
}
