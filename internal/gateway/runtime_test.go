package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daqiaoliang-coder/agent-tool-gateway/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func writeConfig(t *testing.T, path string, cfg config.Config) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".next", data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".next", path); err != nil {
		t.Fatal(err)
	}
}

func runtimeTools(t *testing.T, handler http.Handler, token string) map[string]*mcp.Tool {
	t.Helper()
	rec := mcpRequest(t, handler, "Bearer "+token, "tools/list", map[string]any{})
	var result mcp.ListToolsResult
	if err := json.Unmarshal(rpcResult(t, rec), &result); err != nil {
		t.Fatal(err)
	}
	tools := make(map[string]*mcp.Tool)
	for _, tool := range result.Tools {
		tools[tool.Name] = tool
	}
	return tools
}

func TestRuntimeReleaseDisableAndRollback(t *testing.T) {
	f := newCredentialFixture(t)
	r, err := NewRuntime(f.config, f.gateway.logger)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "gateway.json")
	original := f.config.Clone()
	initial := r.Revision()
	cfg := original.Clone()
	cfg.Tools[0].State = "disabled"
	cfg.Tools[2].State = "deprecated"
	cfg.Tools[2].Version = "2.0"
	cfg.Clients[1].AllowedTools = []string{"beta_tool"}
	writeConfig(t, path, cfg)
	if runtimeTools(t, r.Handler(), alphaToken)["alpha_tool"] == nil {
		t.Fatal("unpublished file affected registry")
	}
	if err := r.ReloadConfig(path); err != nil {
		t.Fatal(err)
	}
	if r.Revision() == initial {
		t.Fatal("configuration revision did not change")
	}
	tools := runtimeTools(t, r.Handler(), alphaToken)
	if len(tools) != 1 || tools["shared_tool"] == nil || tools["shared_tool"].Meta["gateway/state"] != "deprecated" || tools["shared_tool"].Meta["gateway/version"] != "2.0" {
		t.Fatalf("unexpected active registry: %+v", tools)
	}
	if len(runtimeTools(t, r.Handler(), betaToken)) != 1 {
		t.Fatal("new allowlist was not applied")
	}
	rec := mcpRequest(t, r.Handler(), "Bearer "+alphaToken, "tools/call", map[string]any{"name": "alpha_tool", "arguments": map[string]any{"message": "hello"}})
	if !strings.Contains(rec.Body.String(), `unknown tool`) || f.calls.Load() != 0 {
		t.Fatal("disabled tool executed or leaked its schema")
	}
	if rec.Header().Get("X-Config-Revision") != r.Revision() {
		t.Fatal("response did not identify active revision")
	}
	writeConfig(t, path, original)
	if err := r.ReloadConfig(path); err != nil {
		t.Fatal(err)
	}
	if r.Revision() != initial || runtimeTools(t, r.Handler(), alphaToken)["alpha_tool"] == nil {
		t.Fatal("rollback did not restore original registry and revision")
	}
}

func TestRuntimeRejectsInvalidReleaseAtomically(t *testing.T) {
	f := newCredentialFixture(t)
	r, err := NewRuntime(f.config, f.gateway.logger)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "gateway.json")
	initial := r.active.Load()
	for _, tc := range []struct {
		name string
		edit func(*config.Config)
	}{
		{"listener", func(c *config.Config) { c.ListenAddr = "127.0.0.1:10001" }},
		{"concurrency", func(c *config.Config) { c.MaxConcurrentToolCalls++ }},
		{"credential source", func(c *config.Config) { c.CredentialsFile += ".missing" }},
		{"endpoint without version", func(c *config.Config) { c.Tools[0].Endpoint += "/new" }},
		{"schema without version", func(c *config.Config) { c.Tools[0].InputSchema = json.RawMessage(`{"type":"object"}`) }},
		{"invalid schema", func(c *config.Config) {
			c.Tools[0].InputSchema = json.RawMessage(`{"type":"object","properties":{"x":{"type":"string","pattern":"["}}}`)
		}},
		{"unknown allowlist", func(c *config.Config) { c.Clients[0].AllowedTools = []string{"absent"} }},
		{"SDK annotation", func(c *config.Config) {
			c.Tools[0].Version = "2"
			c.Tools[0].InputSchema = json.RawMessage(`{"type":"object","properties":{"x":{"type":"array","x-mcp-header":"X"}}}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := f.config.Clone()
			tc.edit(&cfg)
			writeConfig(t, path, cfg)
			if err := r.ReloadConfig(path); err == nil {
				t.Fatal("invalid release accepted")
			}
			if r.active.Load() != initial || runtimeTools(t, r.Handler(), alphaToken)["alpha_tool"] == nil {
				t.Fatal("failed release changed live snapshot")
			}
		})
	}
	cfg := f.config.Clone()
	cfg.Tools[0].Endpoint += "/new"
	cfg.Tools[0].Version = "2"
	writeConfig(t, path, cfg)
	if err := r.ReloadConfig(path); err != nil {
		t.Fatalf("versioned contract release rejected: %v", err)
	}
	before := r.active.Load()
	if err := os.WriteFile(f.config.CredentialsFile, []byte(`{"clients":`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.ReloadConfig(path); err == nil || r.active.Load() != before {
		t.Fatal("bad credentials did not preserve complete active generation")
	}
	if _, ok := before.authenticate("Bearer " + alphaToken); !ok {
		t.Fatal("rejected release revoked previously active credentials")
	}
}

func TestRuntimeKeepsAdmittedSnapshotAndSharedCapacity(t *testing.T) {
	f := newCredentialFixture(t)
	cfg := f.config.Clone()
	cfg.MaxConcurrentToolCalls = 1
	r, err := NewRuntime(cfg, f.gateway.logger)
	if err != nil {
		t.Fatal(err)
	}
	old := r.active.Load()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	old.client.Transport = recordingTransport(func(req *http.Request) (*http.Response, error) {
		close(entered)
		select {
		case <-release:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"old":true}`)), Header: make(http.Header)}, nil
	})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- mcpRequest(t, r.Handler(), "Bearer "+alphaToken, "tools/call", map[string]any{"name": "alpha_tool", "arguments": map[string]any{"message": "hello"}})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("old call did not enter upstream")
	}
	path := filepath.Join(t.TempDir(), "gateway.json")
	cfg.Tools[0].State = "disabled"
	writeConfig(t, path, cfg)
	if err := r.ReloadConfig(path); err != nil {
		t.Fatal(err)
	}
	if old.metrics != r.active.Load().metrics || old.toolSlots != r.active.Load().toolSlots {
		t.Fatal("release replaced shared metrics or concurrency pool")
	}
	rec := mcpRequest(t, r.Handler(), "Bearer "+alphaToken, "tools/call", map[string]any{"name": "shared_tool", "arguments": map[string]any{}})
	if !strings.Contains(rec.Body.String(), "concurrency limit") {
		t.Fatal("release allowed new requests to bypass occupied slots")
	}
	unblock()
	select {
	case rec = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("admitted call did not complete")
	}
	var result mcp.CallToolResult
	if err := json.Unmarshal(rpcResult(t, rec), &result); err != nil || result.IsError {
		t.Fatalf("admitted request failed after disable: %v", err)
	}
	if rec.Header().Get("X-Config-Revision") != old.revision || len(old.toolSlots) != 0 {
		t.Fatal("admitted request lost its revision or leaked capacity")
	}
}

func TestRuntimeConcurrentConfigAndCredentialReload(t *testing.T) {
	f := newCredentialFixture(t)
	r, err := NewRuntime(f.config, f.gateway.logger)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "gateway.json")
	writeConfig(t, path, f.config)
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			for range 20 {
				g := r.active.Load()
				identity, ok := g.authenticate("Bearer " + alphaToken)
				if !ok || identity.id != "alpha" || identity.credentials.Backends["alpha_tool"].Token != "backend-old-token" {
					t.Error("request observed an inconsistent snapshot")
				}
			}
		})
	}
	wg.Go(func() {
		for range 10 {
			if err := r.ReloadCredentials(); err != nil {
				t.Error(err)
			}
		}
	})
	for i := range 10 {
		cfg := f.config.Clone()
		if i%2 == 0 {
			cfg.Tools[0].State = "disabled"
		}
		writeConfig(t, path, cfg)
		if err := r.ReloadConfig(path); err != nil {
			t.Error(err)
		}
	}
	wg.Wait()
}

func TestRuntimeDrainingAndConfigOwnership(t *testing.T) {
	f := newGatewayFixture(t)
	r, err := NewRuntime(f.config, f.gateway.logger)
	if err != nil {
		t.Fatal(err)
	}
	f.config.Tools[0].State = "disabled"
	f.config.Clients[0].AllowedTools[0] = "beta_tool"
	if runtimeTools(t, r.Handler(), alphaToken)["alpha_tool"] == nil {
		t.Fatal("caller mutated active configuration")
	}
	r.Drain()
	for path, want := range map[string]int{"/healthz": 204, "/readyz": 503, "/mcp": 503} {
		rec := httptest.NewRecorder()
		r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("%s status = %d, want %d", path, rec.Code, want)
		}
	}
	if err := r.ReloadConfig("does-not-exist"); err == nil {
		t.Fatal("draining process accepted publication")
	}
}
