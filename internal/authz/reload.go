package authz

import (
	"context"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

// WatchFile reloads the policy whenever path changes, until ctx is cancelled.
// A policy that fails to compile is logged and skipped, leaving the previous
// version in effect.
func (a *Authorizer) WatchFile(ctx context.Context, path string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	// Watch the directory, not the file: editors and bundle tools often replace
	// a file by renaming a new one over it, which breaks a watch on the inode.
	if err := watcher.Add(filepath.Dir(path)); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case event := <-watcher.Events:
			if filepath.Clean(event.Name) != filepath.Clean(path) {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				a.reloadFile(ctx, path)
			}
		case err := <-watcher.Errors:
			a.logger.Error("policy watch failed", "error", err)
		}
	}
}

func (a *Authorizer) reloadFile(ctx context.Context, path string) {
	policy, err := os.ReadFile(path)
	if err != nil {
		a.logger.Error("read policy failed", "path", path, "error", err)
		return
	}
	if err := a.prepare(ctx, string(policy)); err != nil {
		a.logger.Error("reload policy failed, keeping previous version", "path", path, "error", err)
		return
	}
	a.logger.Info("policy reloaded", "path", path)
}
