package authz

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

// WatchFile reloads the policy whenever the file at path changes, until ctx is
// cancelled. A policy that fails to compile is logged and skipped, leaving the
// previously loaded version in effect, so a bad edit never takes the service down.
func (a *Authorizer) WatchFile(ctx context.Context, path string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create policy watcher: %w", err)
	}
	defer func() {
		if cerr := watcher.Close(); cerr != nil {
			a.logger.Warn("close policy watcher", "path", path, "error", cerr)
		}
	}()

	// Watch the directory rather than the file: editors and bundle tools often
	// replace a file by renaming a new one over it, which breaks a watch bound
	// to the original inode.
	if err := watcher.Add(filepath.Dir(path)); err != nil {
		return fmt.Errorf("watch policy directory: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case event := <-watcher.Events:
			if isPolicyWrite(event, path) {
				a.reloadFile(ctx, path)
			}
		case err := <-watcher.Errors:
			a.logger.Error("policy watcher error", "error", err)
		}
	}
}

// isPolicyWrite reports whether event represents a write or (re)creation of the
// policy file at path, ignoring events for any other file in the directory.
func isPolicyWrite(event fsnotify.Event, path string) bool {
	if filepath.Clean(event.Name) != filepath.Clean(path) {
		return false
	}
	return event.Op&(fsnotify.Write|fsnotify.Create) != 0
}

// reloadFile re-reads and recompiles the policy at path. On any failure the
// previously loaded policy is kept in effect.
func (a *Authorizer) reloadFile(ctx context.Context, path string) {
	policy, err := os.ReadFile(path)
	if err != nil {
		a.logger.Error("read policy for reload", "path", path, "error", err)
		return
	}
	if err := a.prepare(ctx, string(policy)); err != nil {
		a.logger.Error("reload policy, keeping previous version", "path", path, "error", err)
		return
	}
	a.logger.Info("policy reloaded", "path", path)
}
