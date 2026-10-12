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
	"os"
	"strings"
	"time"

	"github.com/daqiaoliang-coder/agent-tool-gateway/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Gateway struct {
	cfg           config.Config
	logger        *slog.Logger
	client        *http.Client
	credentials   []clientCredential
	backendTokens map[string]string
	metricsToken  string
	metrics       *metrics
	toolSlots     chan struct{}
	mcpHandler    http.Handler
}

type clientCredential struct {
	id      string
	token   string
	allowed map[string]struct{}
}

type identityContextKey struct{}
type requestIDContextKey struct{}

func New(cfg config.Config, logger *slog.Logger) (*Gateway, error) {
	if logger == nil {
		logger = slog.Default()
	}
	g := &Gateway{
		cfg:           cfg,
		logger:        logger,
		backendTokens: make(map[string]string),
		metrics:       newMetrics(),
		toolSlots:     make(chan struct{}, cfg.MaxConcurrentToolCalls),
		client: &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	for _, client := range cfg.Clients {
		token := strings.TrimSpace(os.Getenv(client.TokenEnv))
		if len(token) < 32 {
			return nil, fmt.Errorf("client %q token environment variable %s must contain at least 32 characters", client.ID, client.TokenEnv)
		}
		allowed := make(map[string]struct{}, len(client.AllowedTools))
		for _, name := range client.AllowedTools {
			allowed[name] = struct{}{}
		}
		g.credentials = append(g.credentials, clientCredential{id: client.ID, token: token, allowed: allowed})
	}
	if cfg.MetricsTokenEnv != "" {
		g.metricsToken = strings.TrimSpace(os.Getenv(cfg.MetricsTokenEnv))
		if len(g.metricsToken) < 32 {
			return nil, fmt.Errorf("metrics token environment variable %s must contain at least 32 characters", cfg.MetricsTokenEnv)
		}
	}
	for _, tool := range cfg.Tools {
		if tool.BackendTokenEnv == "" {
			continue
		}
		token := strings.TrimSpace(os.Getenv(tool.BackendTokenEnv))
		if token == "" {
			return nil, fmt.Errorf("backend token environment variable %s for tool %q is empty", tool.BackendTokenEnv, tool.Name)
		}
		g.backendTokens[tool.Name] = token
	}

	server := mcp.NewServer(&mcp.Implementation{Name: cfg.ServerName, Version: cfg.ServerVersion}, nil)
	for i := range cfg.Tools {
		toolCfg := cfg.Tools[i]
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
	g.mcpHandler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
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
	if g.metricsToken == "" {
		http.NotFound(w, r)
		return
	}
	if !constantTimeBearerMatch(r.Header.Get("Authorization"), g.metricsToken) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	g.metrics.serveHTTP(w, r)
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

func (g *Gateway) authenticate(header string) (clientCredential, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return clientCredential{}, false
	}
	provided := parts[1]
	for _, credential := range g.credentials {
		if len(provided) == len(credential.token) && subtle.ConstantTimeCompare([]byte(provided), []byte(credential.token)) == 1 {
			return credential, true
		}
	}
	return clientCredential{}, false
}

func (g *Gateway) callTool(ctx context.Context, tool config.Tool, arguments json.RawMessage) (*mcp.CallToolResult, error) {
	started := time.Now()
	identity, ok := ctx.Value(identityContextKey{}).(clientCredential)
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
	result, status, err := g.forward(callCtx, tool, arguments)
	if err != nil {
		g.logCall(ctx, identity.id, tool, status, false, started, "upstream_error")
		return toolError(err.Error()), nil
	}
	g.logCall(ctx, identity.id, tool, status, true, started, "success")
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil
}

func (g *Gateway) forward(ctx context.Context, tool config.Tool, arguments json.RawMessage) ([]byte, int, error) {
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
	if token := g.backendTokens[tool.Name]; token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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

func constantTimeBearerMatch(header, expected string) bool {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) == 1
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
