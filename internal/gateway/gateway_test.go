package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daqiaoliang-coder/agent-tool-gateway/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	alphaToken = "alpha-client-test-token-0000000000"
	betaToken  = "beta-client-test-token-00000000000"
)

type gatewayFixture struct {
	gateway *Gateway
	config  config.Config
	handler http.Handler
	calls   atomic.Int64
	audit   bytes.Buffer
}

func newGatewayFixture(t *testing.T) *gatewayFixture {
	t.Helper()
	f := &gatewayFixture{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"path": r.URL.Path})
	}))
	t.Cleanup(backend.Close)
	t.Setenv("ATG_TEST_ALPHA_TOKEN", alphaToken)
	t.Setenv("ATG_TEST_BETA_TOKEN", betaToken)
	f.config = config.Config{
		Clients: []config.Client{
			{ID: "alpha", TokenEnv: "ATG_TEST_ALPHA_TOKEN", AllowedTools: []string{"alpha_tool", "shared_tool"}},
			{ID: "beta", TokenEnv: "ATG_TEST_BETA_TOKEN", AllowedTools: []string{"beta_tool", "shared_tool"}},
		},
		Tools: []config.Tool{
			{
				Name: "alpha_tool", Description: "Alpha private tool", Method: http.MethodPost, Endpoint: backend.URL + "/alpha",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"message":{"type":"string","minLength":1}},"required":["message"],"additionalProperties":false}`),
			},
			{
				Name: "beta_tool", Description: "Beta private tool", Method: http.MethodPost, Endpoint: backend.URL + "/beta",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"secret_reference":{"type":"string"}},"required":["secret_reference"],"additionalProperties":false}`),
			},
			{
				Name: "shared_tool", Description: "Shared tool", Method: http.MethodGet, Endpoint: backend.URL + "/shared",
				InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
			},
			{
				Name: "unassigned_tool", Description: "Unassigned private tool", Method: http.MethodGet, Endpoint: backend.URL + "/unassigned",
				InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
			},
		},
	}
	if err := f.config.Validate(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.gateway, err = New(f.config, slog.New(slog.NewJSONHandler(&f.audit, nil)))
	if err != nil {
		t.Fatal(err)
	}
	f.handler = f.gateway.Handler()
	return f
}

func mcpRequest(t *testing.T, handler http.Handler, authorization, method string, params any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	req.Header.Set("Mcp-Session-Id", "shared-session-id")
	req.Header.Set("Authorization", authorization)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func rpcResult(t *testing.T, rec *httptest.ResponseRecorder) json.RawMessage {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Error) != 0 || len(response.Result) == 0 {
		t.Fatalf("expected RPC result, got %s", rec.Body.String())
	}
	return response.Result
}

func TestToolDiscoveryIsScopedToAuthenticatedClient(t *testing.T) {
	f := newGatewayFixture(t)
	for _, tc := range []struct {
		name, token string
		want        []string
		hidden      []string
	}{
		{"alpha", alphaToken, []string{"alpha_tool", "shared_tool"}, []string{"beta_tool", "Beta private tool", "secret_reference", "unassigned_tool"}},
		{"beta", betaToken, []string{"beta_tool", "shared_tool"}, []string{"alpha_tool", "Alpha private tool", "message", "unassigned_tool"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for range 5 {
				rec := mcpRequest(t, f.handler, "Bearer "+tc.token, "tools/list", map[string]any{})
				var result mcp.ListToolsResult
				if err := json.Unmarshal(rpcResult(t, rec), &result); err != nil {
					t.Fatal(err)
				}
				var names []string
				for _, tool := range result.Tools {
					names = append(names, tool.Name)
				}
				slices.Sort(names)
				if !slices.Equal(names, tc.want) || result.NextCursor != "" {
					t.Fatalf("tools = %v, cursor = %q; want %v with no next page", names, result.NextCursor, tc.want)
				}
				for _, hidden := range tc.hidden {
					if strings.Contains(rec.Body.String(), hidden) {
						t.Errorf("discovery exposed %q", hidden)
					}
				}
			}
		})
	}
}

func TestAuthorizedToolCalls(t *testing.T) {
	f := newGatewayFixture(t)
	for _, tc := range []struct {
		name, token, tool, path string
		arguments               map[string]any
	}{
		{"alpha private", alphaToken, "alpha_tool", "/alpha", map[string]any{"message": "hello"}},
		{"beta private", betaToken, "beta_tool", "/beta", map[string]any{"secret_reference": "ref"}},
		{"alpha shared", alphaToken, "shared_tool", "/shared", map[string]any{}},
		{"beta shared", betaToken, "shared_tool", "/shared", map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := f.calls.Load()
			rec := mcpRequest(t, f.handler, "Bearer "+tc.token, "tools/call", map[string]any{"name": tc.tool, "arguments": tc.arguments})
			var result mcp.CallToolResult
			if err := json.Unmarshal(rpcResult(t, rec), &result); err != nil {
				t.Fatal(err)
			}
			if result.IsError || len(result.Content) != 1 {
				t.Fatalf("unexpected tool result: %s", rec.Body.String())
			}
			text, ok := result.Content[0].(*mcp.TextContent)
			if !ok || !strings.Contains(text.Text, tc.path) {
				t.Fatalf("unexpected tool content: %v", result.Content)
			}
			if got := f.calls.Load() - before; got != 1 {
				t.Errorf("upstream calls = %d, want 1", got)
			}
		})
	}
}

func TestHiddenToolCallsDoNotRevealSchemasOrReachBackend(t *testing.T) {
	f := newGatewayFixture(t)
	for _, tc := range []struct {
		name, token, tool string
		arguments         map[string]any
	}{
		{"alpha cannot call beta", alphaToken, "beta_tool", map[string]any{"secret_reference": "ref"}},
		{"alpha cannot validate beta", alphaToken, "beta_tool", map[string]any{}},
		{"beta cannot call alpha", betaToken, "alpha_tool", map[string]any{"message": "hello"}},
		{"beta cannot validate alpha", betaToken, "alpha_tool", map[string]any{}},
		{"unassigned", alphaToken, "unassigned_tool", map[string]any{}},
		{"unknown", alphaToken, "unknown_tool", map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := mcpRequest(t, f.handler, "Bearer "+tc.token, "tools/call", map[string]any{"name": tc.tool, "arguments": tc.arguments})
			if rec.Code != http.StatusOK {
				t.Fatalf("HTTP status = %d, body = %s", rec.Code, rec.Body.String())
			}
			var response struct {
				Error *struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Error == nil || response.Error.Code != -32602 || response.Error.Message != fmt.Sprintf("unknown tool %q", tc.tool) {
				t.Fatalf("hidden and unknown tools must be indistinguishable: %s", rec.Body.String())
			}
		})
	}
	if got := f.calls.Load(); got != 0 {
		t.Errorf("unauthorized requests reached the backend %d times", got)
	}
	wantAudits := map[string]int{"alpha:beta_tool": 2, "beta:alpha_tool": 2, "alpha:unassigned_tool": 1}
	for _, line := range strings.Split(strings.TrimSpace(f.audit.String()), "\n") {
		var event struct {
			ClientID  string `json:"client_id"`
			Tool      string `json:"tool"`
			Outcome   string `json:"outcome"`
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event.Outcome != "tool_denied" || event.RequestID == "" {
			t.Errorf("unexpected audit event: %s", line)
		}
		wantAudits[event.ClientID+":"+event.Tool]--
	}
	for key, remaining := range wantAudits {
		if remaining != 0 {
			t.Errorf("audit count mismatch for %s: remaining %d", key, remaining)
		}
	}
}

func TestAuthenticationIsRequiredOnEveryRequest(t *testing.T) {
	f := newGatewayFixture(t)
	_ = rpcResult(t, mcpRequest(t, f.handler, "Bearer "+alphaToken, "tools/list", map[string]any{}))
	for _, authorization := range []string{"", "Bearer invalid", "Basic " + alphaToken, "Bearer " + alphaToken + " extra"} {
		for _, method := range []string{"tools/list", "tools/call"} {
			rec := mcpRequest(t, f.handler, authorization, method, map[string]any{"name": "alpha_tool", "arguments": map[string]any{"message": "hello"}})
			if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Errorf("%s: expected authentication challenge, got %d %s", method, rec.Code, rec.Body.String())
			}
		}
	}
	if got := f.calls.Load(); got != 0 {
		t.Errorf("unauthenticated requests reached the backend %d times", got)
	}
}

func TestAuthorizedArgumentsRemainSchemaValidated(t *testing.T) {
	f := newGatewayFixture(t)
	for _, args := range []map[string]any{{}, {"message": 7}, {"message": ""}, {"message": "hello", "extra": true}} {
		rec := mcpRequest(t, f.handler, "Bearer "+alphaToken, "tools/call", map[string]any{"name": "alpha_tool", "arguments": args})
		var result mcp.CallToolResult
		if err := json.Unmarshal(rpcResult(t, rec), &result); err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Errorf("invalid arguments accepted: %v", args)
		}
	}
	if got := f.calls.Load(); got != 0 {
		t.Errorf("invalid arguments reached the backend %d times", got)
	}
}

func TestCallToolEnforcesIdentityAndAllowlist(t *testing.T) {
	f := newGatewayFixture(t)
	alpha, ok := f.gateway.authenticate("Bearer " + alphaToken)
	if !ok {
		t.Fatal("alpha authentication failed")
	}
	for _, ctx := range []context.Context{
		context.Background(),
		context.WithValue(context.Background(), identityContextKey{}, alpha),
	} {
		result, err := f.gateway.callTool(ctx, f.config.Tools[1], json.RawMessage(`{"secret_reference":"ref"}`))
		if err != nil || result == nil || !result.IsError {
			t.Fatalf("expected execution-layer denial, got result %v, err %v", result, err)
		}
	}
	if got := f.calls.Load(); got != 0 {
		t.Errorf("denied execution reached the backend %d times", got)
	}
}

func TestNewRejectsDuplicateClientTokens(t *testing.T) {
	f := newGatewayFixture(t)
	for _, value := range []string{alphaToken, " \n" + alphaToken + "\t"} {
		t.Setenv("ATG_TEST_BETA_TOKEN", value)
		_, err := New(f.config, nil)
		if err == nil {
			t.Fatal("duplicate client token accepted")
		}
		if strings.Contains(err.Error(), alphaToken) {
			t.Error("configuration error exposed the token")
		}
		if !strings.Contains(err.Error(), "alpha") || !strings.Contains(err.Error(), "beta") {
			t.Errorf("error must identify the conflicting clients: %v", err)
		}
	}
}

func TestClientInfoCannotOverrideBearerIdentity(t *testing.T) {
	f := newGatewayFixture(t)
	_ = rpcResult(t, mcpRequest(t, f.handler, "Bearer "+alphaToken, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "beta", "version": "1.0.0"},
	}))
	rec := mcpRequest(t, f.handler, "Bearer "+alphaToken, "tools/list", map[string]any{"_meta": map[string]any{"client_id": "beta"}})
	var result mcp.ListToolsResult
	if err := json.Unmarshal(rpcResult(t, rec), &result); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range result.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"alpha_tool", "shared_tool"}) {
		t.Fatalf("client-supplied identity affected permissions: %v", names)
	}
}

func TestPermissionChangesTakeEffectAfterRestart(t *testing.T) {
	f := newGatewayFixture(t)
	_ = rpcResult(t, mcpRequest(t, f.handler, "Bearer "+alphaToken, "tools/list", map[string]any{}))
	_ = rpcResult(t, mcpRequest(t, f.handler, "Bearer "+betaToken, "tools/list", map[string]any{}))
	cfg := f.config
	cfg.Clients = []config.Client{{ID: "alpha", TokenEnv: "ATG_TEST_ALPHA_TOKEN", AllowedTools: []string{"shared_tool"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(cfg, f.gateway.logger)
	if err != nil {
		t.Fatal(err)
	}
	handler := restarted.Handler()
	rec := mcpRequest(t, handler, "Bearer "+alphaToken, "tools/list", map[string]any{})
	var result mcp.ListToolsResult
	if err := json.Unmarshal(rpcResult(t, rec), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Tools) != 1 || result.Tools[0].Name != "shared_tool" {
		t.Fatalf("revoked tool is still discoverable: %s", rec.Body.String())
	}
	rec = mcpRequest(t, handler, "Bearer "+alphaToken, "tools/call", map[string]any{"name": "alpha_tool", "arguments": map[string]any{"message": "hello"}})
	var denied struct {
		Error json.RawMessage `json:"error"`
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &denied); err != nil || len(denied.Error) == 0 {
		t.Fatalf("revoked tool call was not rejected: %s", rec.Body.String())
	}
	for _, method := range []string{"tools/list", "tools/call"} {
		rec = mcpRequest(t, handler, "Bearer "+betaToken, method, map[string]any{"name": "shared_tool", "arguments": map[string]any{}})
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("removed client can still use %s: %d", method, rec.Code)
		}
	}
	if got := f.calls.Load(); got != 0 {
		t.Errorf("revoked permissions reached the backend %d times", got)
	}
}

func TestPaginatedDiscoveryRemainsClientScoped(t *testing.T) {
	f := newGatewayFixture(t)
	cfg := f.config
	for i := range mcp.DefaultPageSize + 1 {
		tool := cfg.Tools[2]
		tool.Name = fmt.Sprintf("page_%04d", i)
		cfg.Tools = append(cfg.Tools, tool)
		cfg.Clients[0].AllowedTools = append(cfg.Clients[0].AllowedTools, tool.Name)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	g, err := New(cfg, f.gateway.logger)
	if err != nil {
		t.Fatal(err)
	}
	handler := g.Handler()
	var names []string
	cursor := ""
	for page := 0; ; page++ {
		if page > 2 {
			t.Fatal("pagination did not terminate")
		}
		rec := mcpRequest(t, handler, "Bearer "+alphaToken, "tools/list", map[string]any{"cursor": cursor})
		var result mcp.ListToolsResult
		if err := json.Unmarshal(rpcResult(t, rec), &result); err != nil {
			t.Fatal(err)
		}
		for _, tool := range result.Tools {
			names = append(names, tool.Name)
		}
		cursor = result.NextCursor
		if cursor == "" {
			if page == 0 {
				t.Fatal("expected multiple pages")
			}
			break
		}
		rec = mcpRequest(t, handler, "Bearer "+betaToken, "tools/list", map[string]any{"cursor": cursor})
		var other mcp.ListToolsResult
		if err := json.Unmarshal(rpcResult(t, rec), &other); err != nil {
			t.Fatal(err)
		}
		for _, tool := range other.Tools {
			if !slices.Contains(cfg.Clients[1].AllowedTools, tool.Name) {
				t.Errorf("cross-client cursor exposed %q", tool.Name)
			}
		}
	}
	want := slices.Clone(cfg.Clients[0].AllowedTools)
	slices.Sort(want)
	slices.Sort(names)
	if !slices.Equal(names, want) {
		t.Errorf("paginated tools differ from allowlist: got %d tools, want %d", len(names), len(want))
	}
}
