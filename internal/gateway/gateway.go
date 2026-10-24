package gateway

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
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
	if logger == nil {
		logger = slog.Default()
	}
	g := &Gateway{
		cfg:        cfg,
		logger:     logger,
		identities: make(map[string]clientIdentity, len(cfg.Clients)),
		metrics:    newMetrics(),
		toolSlots:  make(chan struct{}, cfg.MaxConcurrentToolCalls),
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
			if _, allowed := credential.allowed[toolCfg.Name]; !allowed {
				continue
			}
			tool := &mcp.Tool{
				Name:        toolCfg.Name,
				Description: toolCfg.Description,
				InputSchema: json.RawMessage(toolCfg.InputSchema),
			}
			mcp.AddTool(server, tool, func(ctx context.Context, _ *mcp.CallToolRequest, input map[string]any) (*mcp.CallToolResult, any, error) {
				arguments, err := json.Marshal(input)
				if err != nil {
					return nil, nil, fmt.Errorf("encode validated tool input: %w", err)
				}
				result, err := g.callTool(ctx, toolCfg, arguments)
				return result, nil, err
			})
		}
		server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
			return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
				// Hidden tools never reach callTool, so retain denial audits before SDK dispatch.
				if call, ok := req.(*mcp.CallToolRequest); ok && call.Params != nil {
					if _, allowed := credential.allowed[call.Params.Name]; !allowed {
						if tool, known := toolsByName[call.Params.Name]; known {
							g.logCall(ctx, credential.id, tool, 0, false, time.Now(), "tool_denied")
						}
					}
				}
				return next(ctx, method, req)
			}
		})
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

func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("GET /metrics", http.HandlerFunc(g.handleMetrics))
	mux.Handle("/mcp", http.HandlerFunc(g.handleMCP))
	return requestIDMiddleware(mux)
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
	ctx := context.WithValue(r.Context(), identityContextKey{}, credential)
	r = r.WithContext(ctx)
	r.Body = http.MaxBytesReader(w, r.Body, g.cfg.MaxRequestBytes)
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
		g.logCall(ctx, identity.id, tool, 0, false, started, "tool_denied")
		return toolError("client is not allowed to call this tool"), nil
	}
	select {
	case g.toolSlots <- struct{}{}:
		defer func() { <-g.toolSlots }()
	case <-ctx.Done():
		g.logCall(ctx, identity.id, tool, 0, false, started, "cancelled")
		return toolError("tool call cancelled"), nil
	default:
		g.logCall(ctx, identity.id, tool, 0, false, started, "overloaded")
		return toolError("tool gateway is at its configured concurrency limit"), nil
	}

	callCtx, cancel := context.WithTimeout(ctx, g.cfg.Timeout())
	defer cancel()
	result, status, err := g.forward(callCtx, tool, arguments, identity.credentials)
	if err != nil {
		g.logCall(ctx, identity.id, tool, status, false, started, "upstream_error")
		return toolError(err.Error()), nil
	}
	g.logCall(ctx, identity.id, tool, status, true, started, "success")
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil
}

func (g *Gateway) forward(ctx context.Context, tool config.Tool, arguments json.RawMessage, credentials *credentialSnapshot) ([]byte, int, error) {
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
			return nil, 0, errors.New("backend credential is unavailable")
		}
		req.Header.Set("Authorization", "Bearer "+credential.Token)
	}
	if requestID, ok := ctx.Value(requestIDContextKey{}).(string); ok {
		req.Header.Set("X-Request-ID", requestID)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, 0, errors.New("upstream request timed out")
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, 0, errors.New("upstream request cancelled")
		}
		return nil, 0, errors.New("upstream request failed")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, g.cfg.MaxResponseBytes+1))
	if err != nil {
		return nil, resp.StatusCode, errors.New("read upstream response")
	}
	if int64(len(data)) > g.cfg.MaxResponseBytes {
		return nil, resp.StatusCode, errors.New("upstream response exceeded the configured size limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("upstream returned HTTP %d", resp.StatusCode)
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

func (g *Gateway) logCall(ctx context.Context, clientID string, tool config.Tool, status int, success bool, started time.Time, outcome string) {
	elapsed := time.Since(started)
	g.metrics.record(tool.Name, success, elapsed)
	attrs := []any{
		"client_id", clientID,
		"tool", tool.Name,
		"method", tool.Method,
		"status", status,
		"outcome", outcome,
		"duration_ms", elapsed.Milliseconds(),
	}
	if requestID, ok := ctx.Value(requestIDContextKey{}).(string); ok {
		attrs = append(attrs, "request_id", requestID)
	}
	g.logger.Info("tool call completed", attrs...)
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

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var idBytes [16]byte
		if _, err := rand.Read(idBytes[:]); err != nil {
			copy(idBytes[:], []byte(fmt.Sprintf("%016x", time.Now().UnixNano())))
		}
		requestID := hex.EncodeToString(idBytes[:])
		w.Header().Set("X-Request-ID", requestID)
		r = r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, requestID))
		next.ServeHTTP(w, r)
	})
}
