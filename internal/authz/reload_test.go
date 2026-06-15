package authz

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	readerPolicy = `package authz

import rego.v1

default allow := false

allow if "reader" in input.roles
`
	adminPolicy = `package authz

import rego.v1

default allow := false

allow if "admin" in input.roles
`
)

// TestReloadFileSwapsPolicy verifies a valid edit is recompiled and takes effect.
func TestReloadFileSwapsPolicy(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "authz.rego")
	writePolicy(t, path, readerPolicy)

	a, err := NewFromFile(ctx, path, discardLogger())
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if !allows(t, a, "reader") || allows(t, a, "admin") {
		t.Fatal("initial policy should allow reader only")
	}

	writePolicy(t, path, adminPolicy)
	a.reloadFile(ctx, path)

	if allows(t, a, "reader") || !allows(t, a, "admin") {
		t.Fatal("reloaded policy should allow admin only")
	}
}

// TestReloadFileKeepsPreviousOnInvalid verifies that a policy which fails to
// compile is rejected and the previously loaded policy stays in effect.
func TestReloadFileKeepsPreviousOnInvalid(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "authz.rego")
	writePolicy(t, path, readerPolicy)

	a, err := NewFromFile(ctx, path, discardLogger())
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	writePolicy(t, path, "this is not valid rego")
	a.reloadFile(ctx, path)

	if !allows(t, a, "reader") {
		t.Fatal("invalid reload should keep the previous policy in effect")
	}
}

// TestWatchFileReloadsOnChange exercises the end-to-end fsnotify path: a write to
// the watched file is detected and the new policy takes effect without a restart.
func TestWatchFileReloadsOnChange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	path := filepath.Join(t.TempDir(), "authz.rego")
	writePolicy(t, path, readerPolicy)

	a, err := NewFromFile(ctx, path, discardLogger())
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	watchErr := make(chan error, 1)
	go func() { watchErr <- a.WatchFile(ctx, path) }()

	// Rewriting on each poll both drives the change and sidesteps the race where
	// the first write could land before the watcher finishes registering.
	eventually(t, 3*time.Second, func() bool {
		writePolicy(t, path, adminPolicy)
		return allows(t, a, "admin")
	})

	cancel()
	if err := <-watchErr; err != nil {
		t.Fatalf("watch file: %v", err)
	}
}

func writePolicy(t *testing.T, path, policy string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
}

func allows(t *testing.T, a *Authorizer, role string) bool {
	t.Helper()
	allowed, err := a.Allow(context.Background(), Input{Method: "GET", Path: "/resource", Roles: []string{role}})
	if err != nil {
		t.Fatalf("allow: %v", err)
	}
	return allowed
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// eventually fails the test if cond has not become true within timeout.
func eventually(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
