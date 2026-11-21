package gateway

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daqiaoliang-coder/agent-tool-gateway/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Gateway struct {
	cfg        config.Config
	revision   string
	logger     *slog.Logger
	client     *http.Client
	identities map[string]clientIdentity
	secrets    atomic.Pointer[credentialSnapshot]
	reloadMu   sync.Mutex
	metrics    *metrics
	toolSlots  chan struct{}
	mcpHandler http.Handler
}

type clientIdentity struct {
	id      string
	allowed map[string]struct{}
}

type authenticatedClient struct {
	clientIdentity
	credentials *credentialSnapshot
}

type identityContextKey struct{}
type requestIDContextKey struct{}

func New(cfg config.Config, logger *slog.Logger) (*Gateway, error) {
	g, err := newGateway(cfg, logger, newMetrics(), nil)
	if err == nil {
		g.metrics.setRevision(g.revision)
		g.metrics.setLimit(cap(g.toolSlots))
	}
	return g, err
}

func newGateway(cfg config.Config, logger *slog.Logger, metrics *metrics, slots chan struct{}) (*Gateway, error) {
	cfg = cfg.Clone()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	if slots == nil {
		slots = make(chan struct{}, cfg.MaxConcurrentToolCalls)
	}
	g := &Gateway{
		cfg:        cfg,
		revision:   cfg.Revision(),
		logger:     logger,
		identities: make(map[string]clientIdentity, len(cfg.Clients)),
		metrics:    metrics,
		toolSlots:  slots,
		client: &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	snapshot, err := loadCredentials(cfg)
	if err != nil {
		return nil, err
	}
	g.secrets.Store(snapshot)
	for _, client := range cfg.Clients {
		allowed := make(map[string]struct{}, len(client.AllowedTools))
		for _, name := range client.AllowedTools {
			allowed[name] = struct{}{}
		}
		g.identities[client.ID] = clientIdentity{id: client.ID, allowed: allowed}
	}

	toolsByName := make(map[string]config.Tool, len(cfg.Tools))
	for _, tool := range cfg.Tools {
		toolsByName[tool.Name] = tool
	}
	servers := make(map[string]*mcp.Server, len(g.identities))
	for _, credential := range g.identities {
		server := mcp.NewServer(&mcp.Implementation{Name: cfg.ServerName, Version: cfg.ServerVersion}, nil)
		for _, toolCfg := range cfg.Tools {
			if _, allowed := credential.allowed[toolCfg.Name]; !allowed || toolCfg.State == "disabled" {
				continue
			}
			tool := &mcp.Tool{
				Name:        toolCfg.Name,
				Description: toolCfg.Description,
				InputSchema: json.RawMessage(toolCfg.InputSchema),
				Meta: mcp.Meta{
					"gateway/version": toolCfg.Version,
					"gateway/state":   toolCfg.State,
				},
			}
			if err := registerTool(server, tool, func(ctx context.Context, _ *mcp.CallToolRequest, input map[string]any) (*mcp.CallToolResult, any, error) {
				arguments, err := json.Marshal(input)
				if err != nil {
					return nil, nil, fmt.Errorf("encode validated tool input: %w", err)
				}
				result, err := g.callTool(ctx, toolCfg, arguments)
				return result, nil, err
			}); err != nil {
				return nil, err
			}
		}
		server.AddReceivingMiddleware(g.auditRPC(credential, toolsByName))
		servers[credential.id] = server
	}
	g.mcpHandler = mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		credential, ok := r.Context().Value(identityContextKey{}).(authenticatedClient)
		if !ok {
			return nil
		}
		return servers[credential.id]
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	return g, nil
}

func registerTool(server *mcp.Server, tool *mcp.Tool, handler mcp.ToolHandlerFor[map[string]any, any]) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("configured tool could not be registered")
		}
	}()
	mcp.AddTool(server, tool, handler)
	return nil
}

func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /metrics", g.handleMetrics)
	mux.HandleFunc("/mcp", g.handleMCP)
	return requestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Config-Revision", g.revision)
		g.auditHTTP(metricRoute(r.URL.Path), mux).ServeHTTP(w, r)
	}))
}

func (g *Gateway) handleMetrics(w http.ResponseWriter, r *http.Request) {
	snapshot := g.secrets.Load()
	if len(snapshot.Metrics) == 0 {
		http.NotFound(w, r)
		return
	}
	now := time.Now()
	provided := bearerToken(r.Header.Get("Authorization"))
	for _, credential := range snapshot.Metrics {
		if credential.active(now) && constantTimeTokenMatch(provided, credential.Token) {
			g.metrics.serveHTTP(w, r)
			return
		}
	}
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (g *Gateway) handleMCP(w http.ResponseWriter, r *http.Request) {
	credential, ok := g.authenticate(r.Header.Get("Authorization"))
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if observation, ok := r.Context().Value(httpObservationKey{}).(*httpObservation); ok {
		observation.clientID = credential.id
	}
	ctx := context.WithValue(r.Context(), identityContextKey{}, credential)
	r = r.WithContext(ctx)
	r.Body = http.MaxBytesReader(w, r.Body, g.cfg.MaxRequestBytes)
	if observation, ok := ctx.Value(httpObservationKey{}).(*httpObservation); ok {
		r.Body = &observedBody{ReadCloser: r.Body, observation: observation}
	}
	g.mcpHandler.ServeHTTP(w, r)
}

func (g *Gateway) authenticate(header string) (authenticatedClient, bool) {
	provided := bearerToken(header)
	if provided == "" {
		return authenticatedClient{}, false
	}
	snapshot := g.secrets.Load()
	now := time.Now()
	for id, credentials := range snapshot.Clients {
		for _, credential := range credentials {
			if credential.active(now) && constantTimeTokenMatch(provided, credential.Token) {
				return authenticatedClient{clientIdentity: g.identities[id], credentials: snapshot}, true
			}
		}
	}
	return authenticatedClient{}, false
}

func (g *Gateway) callTool(ctx context.Context, tool config.Tool, arguments json.RawMessage) (*mcp.CallToolResult, error) {
	started := time.Now()
	identity, ok := ctx.Value(identityContextKey{}).(authenticatedClient)
	if !ok {
		return toolError("missing authenticated client"), nil
	}
	if _, allowed := identity.allowed[tool.Name]; !allowed {
		g.logCall(ctx, identity.id, tool, 0, started, "tool_denied")
		return toolError("client is not allowed to call this tool"), nil
	}
	if tool.State == "disabled" {
		g.logCall(ctx, identity.id, tool, 0, started, "tool_disabled")
		return toolError("tool is unavailable"), nil
	}
	if ctx.Err() != nil {
		g.logCall(ctx, identity.id, tool, 0, started, "cancelled")
		return toolError("tool call cancelled"), nil
	}
	select {
	case g.toolSlots <- struct{}{}:
		g.metrics.addInFlight(1)
		defer func() {
			g.metrics.addInFlight(-1)
			<-g.toolSlots
		}()
	case <-ctx.Done():
		g.logCall(ctx, identity.id, tool, 0, started, "cancelled")
		return toolError("tool call cancelled"), nil
	default:
		g.logCall(ctx, identity.id, tool, 0, started, "overloaded")
		return toolError("tool gateway is at its configured concurrency limit"), nil
	}

	callCtx, cancel := context.WithTimeout(ctx, g.cfg.Timeout())
	defer cancel()
	result, status, err := g.forward(callCtx, tool, arguments, identity.credentials)
	if err != nil {
		g.logCall(ctx, identity.id, tool, status, started, failureOutcome(err))
		return toolError(err.Error()), nil
	}
	g.logCall(ctx, identity.id, tool, status, started, "success")
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil
}

func (g *Gateway) forward(ctx context.Context, tool config.Tool, arguments json.RawMessage, credentials *credentialSnapshot) (data []byte, status int, err error) {
	ctx = childTraceContext(ctx)
	started := time.Now()
	defer func() {
		outcome := "success"
		if err != nil {
			outcome = failureOutcome(err)
		}
		g.emitAudit(ctx, "upstream request completed", "upstream_request",
			"tool", tool.Name, "tool_version", tool.Version, "method", tool.Method,
			"status", status, "outcome", outcome, "duration_ms", time.Since(started).Milliseconds())
	}()
	endpoint, err := url.Parse(tool.Endpoint)
	if err != nil {
		return nil, 0, errors.New("configured tool endpoint is invalid")
	}
	if tool.Method == http.MethodGet {
		values := make(map[string]json.RawMessage)
		if len(arguments) > 0 && string(arguments) != "null" {
			if err := json.Unmarshal(arguments, &values); err != nil {
				return nil, 0, errors.New("tool arguments must be a JSON object")
			}
		}
		query := endpoint.Query()
		for key, raw := range values {
			value, err := queryValue(raw)
			if err != nil {
				return nil, 0, fmt.Errorf("encode query argument %q: %w", key, err)
			}
			query.Set(key, value)
		}
		endpoint.RawQuery = query.Encode()
	}

	var body io.Reader
	if tool.Method != http.MethodGet {
		if len(arguments) == 0 {
			arguments = json.RawMessage(`{}`)
		}
		body = strings.NewReader(string(arguments))
	}
	req, err := http.NewRequestWithContext(ctx, tool.Method, endpoint.String(), body)
	if err != nil {
		return nil, 0, errors.New("create upstream request")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tool.BackendTokenRequired || tool.BackendTokenEnv != "" {
		credential, ok := credentials.Backends[tool.Name]
		if !ok || !credential.active(time.Now()) {
			return nil, 0, &callFailure{"backend_credential_unavailable", "backend credential is unavailable"}
		}
		req.Header.Set("Authorization", "Bearer "+credential.Token)
	}
	if requestID, ok := ctx.Value(requestIDContextKey{}).(string); ok {
		req.Header.Set("X-Request-ID", requestID)
	}

	if trace, ok := ctx.Value(traceContextKey{}).(traceContext); ok {
		req.Header.Set("traceparent", trace.header())
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, 0, upstreamFailure(ctx, "upstream request failed")
	}
	defer resp.Body.Close()
	data, err = io.ReadAll(io.LimitReader(resp.Body, g.cfg.MaxResponseBytes+1))
	if err != nil {
		return nil, resp.StatusCode, upstreamFailure(ctx, "read upstream response")
	}
	if int64(len(data)) > g.cfg.MaxResponseBytes {
		return nil, resp.StatusCode, &callFailure{"response_too_large", "upstream response exceeded the configured size limit"}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, &callFailure{"upstream_http_error", fmt.Sprintf("upstream returned HTTP %d", resp.StatusCode)}
	}
	return data, resp.StatusCode, nil
}

func queryValue(raw json.RawMessage) (string, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	if text, ok := value.(string); ok {
		return text, nil
	}
	return string(raw), nil
}

func (g *Gateway) logCall(ctx context.Context, clientID string, tool config.Tool, status int, started time.Time, outcome string) {
	if observation, ok := ctx.Value(toolObservationKey{}).(*toolObservation); ok {
		observation.outcome, observation.status = outcome, status
		return
	}
	g.completeToolAudit(ctx, clientID, tool, status, started, outcome)
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.Handler().ServeHTTP(w, r)
}

func toolError(message string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: message}}}
}

func bearerToken(header string) string {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func constantTimeTokenMatch(provided, expected string) bool {
	return len(provided) == len(expected) && subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}
