package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/daqiaoliang-coder/agent-tool-gateway/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type toolObservationKey struct{}
type httpObservationKey struct{}
type traceContextKey struct{}

type toolObservation struct {
	outcome string
	status  int
}

type httpObservation struct {
	clientID      string
	rpcHandled    atomic.Bool
	tooLarge      atomic.Bool
	batchRejected atomic.Bool
}

type observedBody struct {
	io.ReadCloser
	observation *httpObservation
	started     bool
}

func (b *observedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if !b.started {
		if prefix := bytes.TrimLeft(p[:n], " \t\r\n"); len(prefix) > 0 {
			b.started = true
			if prefix[0] == '[' {
				b.observation.batchRejected.Store(true)
				return 0, errors.New("JSON-RPC batches are not supported")
			}
		}
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		b.observation.tooLarge.Store(true)
	}
	return n, err
}

type traceContext struct {
	traceID, spanID, parentID, flags string
}

func randomHex(size int) string {
	b := make([]byte, size)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func validTraceHex(s string, size int) bool {
	if len(s) != size || s != strings.ToLower(s) || strings.Trim(s, "0") == "" {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func requestTrace(header string) traceContext {
	trace := traceContext{traceID: randomHex(16), spanID: randomHex(8), flags: "00"}
	parts := strings.Split(header, "-")
	if len(parts) == 4 && parts[0] == "00" && validTraceHex(parts[1], 32) && validTraceHex(parts[2], 16) && len(parts[3]) == 2 && parts[3] == strings.ToLower(parts[3]) {
		if flags, err := hex.DecodeString(parts[3]); err == nil {
			trace.traceID, trace.parentID = parts[1], parts[2]
			if flags[0]&1 != 0 {
				trace.flags = "01"
			}
		}
	}
	return trace
}

func (t traceContext) header() string {
	return "00-" + t.traceID + "-" + t.spanID + "-" + t.flags
}

func childTraceContext(ctx context.Context) context.Context {
	trace, ok := ctx.Value(traceContextKey{}).(traceContext)
	if !ok {
		trace = requestTrace("")
	}
	trace.parentID, trace.spanID = trace.spanID, randomHex(8)
	return context.WithValue(ctx, traceContextKey{}, trace)
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := randomHex(16)
		parent := ""
		if values := r.Header.Values("traceparent"); len(values) == 1 {
			parent = values[0]
		}
		trace := requestTrace(parent)
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("traceparent", trace.header())
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, requestID)
		ctx = context.WithValue(ctx, traceContextKey{}, trace)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (g *Gateway) emitAudit(ctx context.Context, message, event string, attrs ...any) {
	attrs = append(attrs, "event", event, "config_revision", g.revision)
	if requestID, ok := ctx.Value(requestIDContextKey{}).(string); ok {
		attrs = append(attrs, "request_id", requestID)
	}
	if trace, ok := ctx.Value(traceContextKey{}).(traceContext); ok {
		attrs = append(attrs, "trace_id", trace.traceID, "span_id", trace.spanID, "parent_span_id", trace.parentID)
	}
	g.logger.InfoContext(ctx, message, attrs...)
}

func (g *Gateway) completeToolAudit(ctx context.Context, clientID string, tool config.Tool, status int, started time.Time, outcome string) {
	elapsed := time.Since(started)
	g.metrics.record(tool.Name, outcome, elapsed)
	g.emitAudit(ctx, "tool call completed", "tool_call",
		"client_id", clientID, "tool", tool.Name, "tool_version", tool.Version, "tool_state", tool.State,
		"method", tool.Method, "status", status, "outcome", outcome, "duration_ms", elapsed.Milliseconds())
}

func (g *Gateway) auditRPC(identity clientIdentity, tools map[string]config.Tool) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if observation, ok := ctx.Value(httpObservationKey{}).(*httpObservation); ok {
				observation.rpcHandled.Store(true)
			}
			started := time.Now()
			call, ok := req.(*mcp.CallToolRequest)
			if !ok {
				result, err := next(ctx, method, req)
				outcome := "success"
				if err != nil {
					outcome = "protocol_error"
				}
				g.emitAudit(ctx, "MCP operation completed", "mcp_operation", "client_id", identity.id,
					"rpc_method", rpcMethod(method), "outcome", outcome, "duration_ms", time.Since(started).Milliseconds())
				return result, err
			}
			ctx = childTraceContext(ctx)
			tool := config.Tool{Name: "[unknown]"}
			observation := &toolObservation{outcome: "unknown_tool"}
			if call.Params != nil {
				if configured, known := tools[call.Params.Name]; known {
					tool = configured
					_, allowed := identity.allowed[tool.Name]
					switch {
					case !allowed:
						observation.outcome = "tool_denied"
					case tool.State == "disabled":
						observation.outcome = "tool_disabled"
					default:
						observation.outcome = "invalid_arguments"
					}
				}
			}
			ctx = context.WithValue(ctx, toolObservationKey{}, observation)
			result, err := next(ctx, method, req)
			g.completeToolAudit(ctx, identity.id, tool, observation.status, started, observation.outcome)
			return result, err
		}
	}
}

func rpcMethod(method string) string {
	switch method {
	case "initialize", "ping", "tools/list", "tools/call", "resources/list", "resources/templates/list", "resources/read", "prompts/list", "prompts/get", "notifications/initialized", "notifications/cancelled", "logging/setLevel", "completion/complete":
		return method
	default:
		return "[other]"
	}
}

func httpMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
		return method
	default:
		return "[other]"
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) WriteHeader(status int) {
	if w.status == 0 && status >= 200 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (g *Gateway) auditHTTP(route string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		observation := &httpObservation{}
		r = r.WithContext(context.WithValue(r.Context(), httpObservationKey{}, observation))
		recorder := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		outcome := "success"
		switch {
		case r.Context().Err() != nil:
			outcome = "cancelled"
		case status == http.StatusUnauthorized:
			outcome = "authentication_failed"
		case observation.tooLarge.Load() || status == http.StatusRequestEntityTooLarge:
			outcome = "request_too_large"
		case observation.batchRejected.Load():
			outcome = "protocol_error"
		case status >= 500:
			outcome = "internal_error"
		case status >= 400:
			outcome = "request_rejected"
		case route == "/mcp" && r.Method == http.MethodPost && status == http.StatusOK && !observation.rpcHandled.Load():
			// SDK parameter decoding can fail with HTTP 200 before receiving middleware.
			outcome = "protocol_error"
		}
		elapsed := time.Since(started)
		g.metrics.recordHTTP(route, httpMethod(r.Method), outcome, status, elapsed)
		// Successful health checks and scrapes are counted without repetitive logs.
		if (route != "/metrics" && route != "/healthz" && route != "/readyz") || status >= 400 {
			g.emitAudit(r.Context(), "HTTP request completed", "http_request", "route", route,
				"client_id", observation.clientID, "method", httpMethod(r.Method), "status", status,
				"outcome", outcome, "duration_ms", elapsed.Milliseconds())
		}
	})
}

type callFailure struct {
	outcome string
	message string
}

func (e *callFailure) Error() string { return e.message }

func failureOutcome(err error) string {
	var failure *callFailure
	if errors.As(err, &failure) {
		return failure.outcome
	}
	return "internal_error"
}

func upstreamFailure(ctx context.Context, message string) error {
	switch ctx.Err() {
	case context.DeadlineExceeded:
		return &callFailure{"timeout", "upstream request timed out"}
	case context.Canceled:
		return &callFailure{"cancelled", "upstream request cancelled"}
	default:
		return &callFailure{"upstream_error", message}
	}
}
