package gateway

import (
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/daqiaoliang-coder/agent-tool-gateway/internal/config"
)

type Runtime struct {
	active   atomic.Pointer[Gateway]
	mu       sync.Mutex
	draining atomic.Bool
}

func NewRuntime(cfg config.Config, logger *slog.Logger) (*Runtime, error) {
	g, err := New(cfg, logger)
	if err != nil {
		return nil, err
	}
	r := &Runtime{}
	r.active.Store(g)
	g.logger.Info("configuration activated", "event", "config_reload", "outcome", "startup", "config_revision", g.revision)
	return r, nil
}

func (r *Runtime) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		g := r.active.Load()
		if r.draining.Load() && (req.URL.Path == "/readyz" || req.URL.Path == "/mcp") {
			requestIDMiddleware(g.auditHTTP(req.URL.Path, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Config-Revision", g.revision)
				http.Error(w, "gateway is draining", http.StatusServiceUnavailable)
			}))).ServeHTTP(w, req)
			return
		}
		g.ServeHTTP(w, req)
	})
}

func (r *Runtime) Drain() { r.draining.Store(true) }

func (r *Runtime) Revision() string { return r.active.Load().revision }

func (r *Runtime) ReloadCredentials() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active.Load().ReloadCredentials()
}

func (r *Runtime) ReloadConfig(path string) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	previous := r.active.Load()
	reason := "validation_failed"
	defer func() {
		outcome := "success"
		if err != nil {
			outcome = "rejected"
			previous.logger.Error("configuration reload rejected; previous configuration remains active",
				"event", "config_reload", "outcome", outcome, "reason", reason, "config_revision", previous.revision)
		} else {
			previous.logger.Info("configuration reloaded", "event", "config_reload", "outcome", outcome,
				"previous_revision", previous.revision, "config_revision", r.Revision())
		}
		previous.metrics.recordReload("config", outcome)
	}()
	if r.draining.Load() {
		reason = "draining"
		return errors.New("configuration reload is unavailable while draining")
	}
	cfg, err := config.Load(path)
	if err != nil {
		return errors.New("configuration validation failed")
	}
	if cfg.ListenAddr != previous.cfg.ListenAddr || cfg.MaxConcurrentToolCalls != previous.cfg.MaxConcurrentToolCalls || cfg.CredentialsFile != previous.cfg.CredentialsFile {
		reason = "restart_required"
		return errors.New("listen_addr, max_concurrent_tool_calls and credentials_file changes require a restart")
	}
	oldTools := make(map[string]config.Tool, len(previous.cfg.Tools))
	for _, tool := range previous.cfg.Tools {
		oldTools[tool.Name] = tool
	}
	for _, tool := range cfg.Tools {
		if old, exists := oldTools[tool.Name]; exists && old.Version == tool.Version && toolContract(old) != toolContract(tool) {
			reason = "tool_version_required"
			return errors.New("tool contract changes require a different version")
		}
	}
	candidate, err := newGateway(cfg, previous.logger, previous.metrics, previous.toolSlots)
	if err != nil {
		reason = "credentials_invalid"
		return errors.New("configuration credentials validation failed")
	}
	r.active.Store(candidate)
	candidate.metrics.setRevision(candidate.revision)
	return nil
}

func toolContract(tool config.Tool) string {
	tool.State, tool.Description = "", ""
	return (config.Config{Tools: []config.Tool{tool}}).Revision()
}
