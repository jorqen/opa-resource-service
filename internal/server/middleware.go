package server

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jorqen/opa-resource-service/internal/auth"
	"github.com/jorqen/opa-resource-service/internal/authz"
)

type contextKey struct{}

var claimsContextKey contextKey

// authMiddleware authenticates the bearer token and asks the Authorizer for an
// allow decision before passing the request to next.
func authMiddleware(authorizer Authorizer, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}

		claims, err := auth.ParseClaims(token)
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "invalid bearer token")
			return
		}

		allowed, err := authorizer.Allow(r.Context(), authz.Input{
			Method: r.Method,
			Path:   r.URL.Path,
			Roles:  claims.Roles,
		})
		if err != nil {
			logger.Error("authorization failed", "error", err)
			writeError(w, http.StatusInternalServerError, "authorization error")
			return
		}
		if !allowed {
			writeError(w, http.StatusForbidden, "access denied: insufficient role")
			return
		}

		next.ServeHTTP(w, r.WithContext(withClaims(r.Context(), claims)))
	})
}

func bearerToken(r *http.Request) (string, bool) {
	const scheme = "bearer "
	header := r.Header.Get("Authorization")
	if len(header) < len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	token := strings.TrimSpace(header[len(scheme):])
	return token, token != ""
}

func withClaims(ctx context.Context, claims auth.Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

func claimsFrom(ctx context.Context) (auth.Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(auth.Claims)
	return claims, ok
}
