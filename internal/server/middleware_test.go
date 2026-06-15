package server_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jorqen/opa-resource-service/internal/authz"
	"github.com/jorqen/opa-resource-service/internal/server"
)

var errBoom = errors.New("boom")

type stubAuthorizer struct {
	allow bool
	err   error
}

func (s stubAuthorizer) Allow(context.Context, authz.Input) (bool, error) {
	return s.allow, s.err
}

func TestResourceAuthorization(t *testing.T) {
	cases := []struct {
		name       string
		authHeader string
		authorizer server.Authorizer
		wantStatus int
	}{
		{"allowed", bearer(t, "reader"), stubAuthorizer{allow: true}, http.StatusOK},
		{"forbidden", bearer(t, "guest"), stubAuthorizer{allow: false}, http.StatusForbidden},
		{"missing token", "", stubAuthorizer{allow: true}, http.StatusUnauthorized},
		{"malformed token", "Bearer not-a-jwt", stubAuthorizer{allow: true}, http.StatusUnauthorized},
		{"authorizer error", bearer(t, "reader"), stubAuthorizer{err: errBoom}, http.StatusInternalServerError},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/resource", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()

			server.New(tc.authorizer, logger).ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("content-type = %q, want application/json", ct)
			}
		})
	}
}

func bearer(t *testing.T, roles ...string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"preferred_username": "tester",
		"realm_access":       map[string]any{"roles": roles},
	})
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	token := encode([]byte(`{"alg":"none"}`)) + "." + encode(payload) + "." + encode([]byte("sig"))
	return "Bearer " + token
}
