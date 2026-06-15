// Package auth extracts identity and roles from Keycloak bearer tokens.
package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// ErrInvalidToken is returned when a token is not a well-formed JWT.
var ErrInvalidToken = errors.New("invalid token")

// Claims holds the subset of Keycloak JWT claims the service relies on.
type Claims struct {
	Subject  string
	Username string
	Roles    []string
}

// ParseClaims decodes the claims of a Keycloak JWT.
//
// The signature is intentionally not verified: in production the token would be
// validated against Keycloak's JWKS endpoint. Keeping that out of scope lets the
// claims be supplied by a mocked, unsigned token.
func ParseClaims(token string) (Claims, error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return Claims{}, ErrInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}

	var body struct {
		Subject     string `json:"sub"`
		Username    string `json:"preferred_username"`
		RealmAccess struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return Claims{}, ErrInvalidToken
	}

	return Claims{
		Subject:  body.Subject,
		Username: body.Username,
		Roles:    body.RealmAccess.Roles,
	}, nil
}
