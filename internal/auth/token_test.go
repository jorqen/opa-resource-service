package auth_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/jorqen/opa-resource-service/internal/auth"
)

func TestParseClaims(t *testing.T) {
	token := makeToken(t, map[string]any{
		"sub":                "user-123",
		"preferred_username": "alice",
		"realm_access":       map[string]any{"roles": []string{"reader", "admin"}},
	})

	claims, err := auth.ParseClaims(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Errorf("subject = %q, want %q", claims.Subject, "user-123")
	}
	if claims.Username != "alice" {
		t.Errorf("username = %q, want %q", claims.Username, "alice")
	}
	if want := []string{"reader", "admin"}; !slices.Equal(claims.Roles, want) {
		t.Errorf("roles = %v, want %v", claims.Roles, want)
	}
}

func TestParseClaimsInvalid(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"two segments":     "header.payload",
		"bad base64":       "header.@@@.signature",
		"payload not json": "header." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".signature",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := auth.ParseClaims(token); !errors.Is(err, auth.ErrInvalidToken) {
				t.Errorf("err = %v, want ErrInvalidToken", err)
			}
		})
	}
}

func makeToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	return encode([]byte(`{"alg":"RS256"}`)) + "." + encode(payload) + "." + encode([]byte("signature"))
}
