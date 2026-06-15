// Package authz evaluates authorization decisions with Open Policy Agent.
package authz

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"

	"github.com/open-policy-agent/opa/rego"
)

const (
	moduleName    = "authz.rego"
	decisionQuery = "data.authz.allow"
)

// Input is the document evaluated by the policy on every request.
type Input struct {
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Roles  []string `json:"roles"`
}

// Authorizer evaluates a prepared Rego query. It is safe for concurrent use, and
// its policy may be swapped at runtime (see WatchFile).
type Authorizer struct {
	logger *slog.Logger
	query  atomic.Pointer[rego.PreparedEvalQuery]
}

// New prepares policy for evaluation. A nil logger falls back to slog.Default.
func New(ctx context.Context, policy string, logger *slog.Logger) (*Authorizer, error) {
	if logger == nil {
		logger = slog.Default()
	}
	a := &Authorizer{logger: logger}
	if err := a.prepare(ctx, policy); err != nil {
		return nil, err
	}
	return a, nil
}

// NewFromFile reads the policy from path and prepares it.
func NewFromFile(ctx context.Context, path string, logger *slog.Logger) (*Authorizer, error) {
	policy, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return New(ctx, string(policy), logger)
}

// Allow reports whether the policy permits the request described by in.
func (a *Authorizer) Allow(ctx context.Context, in Input) (bool, error) {
	result, err := a.query.Load().Eval(ctx, rego.EvalInput(in))
	if err != nil {
		return false, fmt.Errorf("evaluate policy: %w", err)
	}
	return result.Allowed(), nil
}

// prepare compiles policy and atomically swaps it in as the active query.
func (a *Authorizer) prepare(ctx context.Context, policy string) error {
	query, err := rego.New(
		rego.Query(decisionQuery),
		rego.Module(moduleName, policy),
	).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("prepare policy: %w", err)
	}
	a.query.Store(&query)
	return nil
}
