package authz_test

import (
	"context"
	"testing"

	"github.com/jorqen/opa-resource-service/internal/authz"
)

func TestAllow(t *testing.T) {
	authorizer, err := authz.NewFromFile(context.Background(), "../../policy/authz.rego", nil)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	cases := []struct {
		name string
		in   authz.Input
		want bool
	}{
		{"admin on any method", authz.Input{Method: "DELETE", Path: "/resource", Roles: []string{"admin"}}, true},
		{"reader on get", authz.Input{Method: "GET", Path: "/resource", Roles: []string{"reader"}}, true},
		{"reader on post", authz.Input{Method: "POST", Path: "/resource", Roles: []string{"reader"}}, false},
		{"unknown role", authz.Input{Method: "GET", Path: "/resource", Roles: []string{"editor"}}, false},
		{"no roles", authz.Input{Method: "GET", Path: "/resource", Roles: nil}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := authorizer.Allow(context.Background(), tc.in)
			if err != nil {
				t.Fatalf("allow: %v", err)
			}
			if got != tc.want {
				t.Errorf("allow = %v, want %v", got, tc.want)
			}
		})
	}
}
