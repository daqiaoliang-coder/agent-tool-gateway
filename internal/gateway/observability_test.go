package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type auditEvent struct {
	Event        string `json:"event"`
	Outcome      string `json:"outcome"`
	Tool         string `json:"tool"`
	ToolVersion  string `json:"tool_version"`
	ClientID     string `json:"client_id"`
	RequestID    string `json:"request_id"`
	Revision     string `json:"config_revision"`
	TraceID      string `json:"trace_id"`
	SpanID       string `json:"span_id"`
	ParentSpanID string `json:"parent_span_id"`
	Status       int    `json:"status"`
}

func auditEvents(t *testing.T, logs string, kind string) []auditEvent {
	t.Helper()
	var events []auditEvent
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		if line == "" {
			continue
		}
		var event auditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event.Event == kind {
			events = append(events, event)
		}
	}
	return events
}

func TestAuditEveryToolOutcomeExactlyOnce(t *testing.T) {
	const marker = "DO_NOT_LOG_ARGUMENT_OR_UNKNOWN_TOOL"
	for _, tc := range []struct {
		name, tool, outcome string
		args                map[string]any
	}{
		{"success", "alpha_tool", "success", map[string]any{"message": marker}},
		{"schema rejection", "alpha_tool", "invalid_arguments", map[string]any{"message": 7, marker: marker}},
		{"permission rejection", "beta_tool", "tool_denied", map[string]any{"secret_reference": marker}},
		{"unknown", marker, "unknown_tool", map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGatewayFixture(t)
			rec := mcpRequest(t, f.handler, "Bearer "+alphaToken, "tools/call", map[string]any{"name": tc.tool, "arguments": tc.args})
			events := auditEvents(t, f.audit.String(), "tool_call")
			if len(events) != 1 || events[0].Outcome != tc.outcome {
				t.Fatalf("tool audit should occur once with %s: %+v", tc.outcome, events)
			}
			event := events[0]
			if event.ClientID != "alpha" || event.RequestID != rec.Header().Get("X-Request-ID") || len(event.TraceID) != 32 || len(event.SpanID) != 16 || event.Revision != f.gateway.revision {
				t.Fatalf("missing correlation: %+v", event)
			}
			tool := tc.tool
			if tc.outcome == "unknown_tool" {
				tool = "[unknown]"
			}
			metrics := httptest.NewRecorder()
			f.gateway.metrics.serveHTTP(metrics, nil)
			if !strings.Contains(metrics.Body.String(), `agent_tool_gateway_tool_calls_total{tool="`+tool+`",outcome="`+tc.outcome+`"} 1`) {
				t.Fatalf("missing classified counter: %s", metrics.Body.String())
			}
			if strings.Contains(f.audit.String(), marker) || strings.Contains(f.audit.String(), alphaToken) || strings.Contains(metrics.Body.String(), marker) {
				t.Fatal("untrusted argument/name or credentials leaked into telemetry")
			}
			if tc.outcome != "success" && f.calls.Load() != 0 {
				t.Fatal("rejected call reached upstream")
			}
		})
	}
}

func TestHTTPRejectionAuditsAndTransport(t *testing.T) {
	for _, tc := range []struct {
		name, body, authorization, accept string
		wantStatus                        int
		wantOutcome                       string
	}{
		{"authentication", `{}`, "Bearer DO_NOT_LOG_AUTH", "application/json, text/event-stream", 401, "authentication_failed"},
		{"invalid JSON", `{"DO_NOT_LOG_BODY":`, "Bearer " + alphaToken, "application/json, text/event-stream", 400, "request_rejected"},
		{"unacceptable", `{}`, "Bearer " + alphaToken, "text/plain", 400, "request_rejected"},
		{"unknown method", `{"jsonrpc":"2.0","id":1,"method":"DO_NOT_LOG_METHOD","params":{}}`, "Bearer " + alphaToken, "application/json, text/event-stream", 400, "request_rejected"},
		{"missing params", `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`, "Bearer " + alphaToken, "application/json, text/event-stream", 400, "request_rejected"},
		{"invalid params type", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":42}}`, "Bearer " + alphaToken, "application/json, text/event-stream", 200, "protocol_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGatewayFixture(t)
			req := httptest.NewRequest(http.MethodPost, "/mcp?DO_NOT_LOG_QUERY=private", strings.NewReader(tc.body))
			req.Header.Set("Authorization", tc.authorization)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", tc.accept)
			rec := httptest.NewRecorder()
			f.handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			events := auditEvents(t, f.audit.String(), "http_request")
			if len(events) != 1 || events[0].Outcome != tc.wantOutcome || events[0].RequestID == "" || events[0].Status != tc.wantStatus {
				t.Fatalf("missing HTTP rejection audit: %+v", events)
			}
			if strings.Contains(f.audit.String(), "DO_NOT_LOG") || strings.Contains(f.audit.String(), alphaToken) {
				t.Fatal("HTTP audit leaked caller-controlled data")
			}
		})
	}
}

func TestUpstreamOutcomesAndSaturation(t *testing.T) {
	for _, outcome := range []string{"upstream_error", "upstream_http_error", "timeout", "response_too_large", "overloaded", "cancelled"} {
		t.Run(outcome, func(t *testing.T) {
			f := newGatewayFixture(t)
			cfg := f.config.Clone()
			cfg.RequestTimeout, cfg.MaxResponseBytes = "15ms", 8
			g, err := New(cfg, f.gateway.logger)
			if err != nil {
				t.Fatal(err)
			}
			g.client.Transport = recordingTransport(func(req *http.Request) (*http.Response, error) {
				switch outcome {
				case "upstream_error":
					return nil, errors.New("DO_NOT_LOG_UPSTREAM_ERROR")
				case "timeout":
					<-req.Context().Done()
					return nil, req.Context().Err()
				case "upstream_http_error":
					return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
				default:
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("DO_NOT_LOG_RESPONSE_BODY"))}, nil
				}
			})
			if outcome == "overloaded" {
				for range cap(g.toolSlots) {
					g.toolSlots <- struct{}{}
				}
			}
			if outcome == "cancelled" {
				identity, _ := g.authenticate("Bearer " + alphaToken)
				ctx, cancel := context.WithCancel(context.WithValue(t.Context(), identityContextKey{}, identity))
				cancel()
				_, _ = g.callTool(ctx, g.cfg.Tools[0], json.RawMessage(`{"message":"hello"}`))
			} else {
				rec := mcpRequest(t, g.Handler(), "Bearer "+alphaToken, "tools/call", map[string]any{"name": "alpha_tool", "arguments": map[string]any{"message": "hello"}})
				var result mcp.CallToolResult
				if err := json.Unmarshal(rpcResult(t, rec), &result); err != nil || !result.IsError {
					t.Fatalf("expected safe tool error: %v", err)
				}
			}
			events := auditEvents(t, f.audit.String(), "tool_call")
			if len(events) != 1 || events[0].Outcome != outcome {
				t.Fatalf("incorrect failure classification: %+v", events)
			}
			if strings.Contains(f.audit.String(), "DO_NOT_LOG") {
				t.Fatal("upstream response/error appeared in audit")
			}
		})
	}
}

func TestTraceCorrelationAndPropagation(t *testing.T) {
	f := newGatewayFixture(t)
	const parent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
	var upstream http.Header
	f.gateway.client.Transport = recordingTransport(func(req *http.Request) (*http.Response, error) {
		upstream = req.Header.Clone()
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"alpha_tool","arguments":{"message":"hello"}}}`)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+alphaToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	req.Header.Set("traceparent", parent)
	req.Header.Set("tracestate", "private=DO_NOT_LOG")
	req.Header.Set("baggage", "secret=DO_NOT_LOG")
	req.Header.Set("X-Request-ID", "DO_NOT_LOG_CALLER_ID")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	_ = rpcResult(t, rec)
	httpEvents := auditEvents(t, f.audit.String(), "http_request")
	tools := auditEvents(t, f.audit.String(), "tool_call")
	backends := auditEvents(t, f.audit.String(), "upstream_request")
	if len(httpEvents) != 1 || len(tools) != 1 || len(backends) != 1 {
		t.Fatalf("missing trace events: %s", f.audit.String())
	}
	h, tool, backend := httpEvents[0], tools[0], backends[0]
	if h.TraceID != strings.Split(parent, "-")[1] || h.ParentSpanID != strings.Split(parent, "-")[2] || tool.TraceID != h.TraceID || backend.TraceID != h.TraceID || tool.ParentSpanID != h.SpanID || backend.ParentSpanID != tool.SpanID {
		t.Fatalf("broken parent/child trace: %s", f.audit.String())
	}
	if upstream.Get("traceparent") != "00-"+backend.TraceID+"-"+backend.SpanID+"-01" || upstream.Get("X-Request-ID") != rec.Header().Get("X-Request-ID") {
		t.Fatal("upstream did not receive correlated child trace and request ID")
	}
	if upstream.Get("baggage") != "" || upstream.Get("tracestate") != "" || strings.Contains(f.audit.String(), "DO_NOT_LOG") {
		t.Fatal("private trace headers or caller request ID were propagated/logged")
	}
}

func TestMixedLegacyBatchesAreRejected(t *testing.T) {
	for _, version := range []string{"", "2025-03-26", "2025-06-18"} {
		t.Run(version, func(t *testing.T) {
			f := newGatewayFixture(t)
			body := ` [{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":42,"arguments":{"private":"DO_NOT_LOG_BATCH"}}}]`
			req := httptest.NewRequest(http.MethodPost, "/mcp", iotest.OneByteReader(strings.NewReader(body)))
			req.Header.Set("Authorization", "Bearer "+alphaToken)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("MCP-Protocol-Version", version)
			rec := httptest.NewRecorder()
			f.handler.ServeHTTP(rec, req)
			events := auditEvents(t, f.audit.String(), "http_request")
			if rec.Code != 400 || len(events) != 1 || events[0].Outcome != "protocol_error" || len(auditEvents(t, f.audit.String(), "mcp_operation")) != 0 {
				t.Fatalf("batch bypassed single-message policy: %d %+v", rec.Code, events)
			}
			if strings.Contains(f.audit.String(), "DO_NOT_LOG_BATCH") || f.calls.Load() != 0 {
				t.Fatal("batch executed or leaked its payload")
			}
		})
	}
}

func TestRouterRejectionsAreObserved(t *testing.T) {
	f := newGatewayFixture(t)
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPost, "/metrics", 405},
		{http.MethodGet, "/DO_NOT_LOG_UNMATCHED_PATH", 404},
	} {
		f.audit.Reset()
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		events := auditEvents(t, f.audit.String(), "http_request")
		if rec.Code != tc.status || len(events) != 1 || events[0].Outcome != "request_rejected" {
			t.Fatalf("router rejection was not observed once: %d %+v", rec.Code, events)
		}
	}
	metrics := httptest.NewRecorder()
	f.gateway.metrics.serveHTTP(metrics, nil)
	if strings.Contains(f.audit.String(), "DO_NOT_LOG") || strings.Contains(metrics.Body.String(), "DO_NOT_LOG") || !strings.Contains(metrics.Body.String(), `route="[other]"`) {
		t.Fatal("unmatched paths are not normalized")
	}
}

func TestRequestSizeRejectionIsClassified(t *testing.T) {
	f := newGatewayFixture(t)
	cfg := f.config.Clone()
	cfg.MaxRequestBytes = 64
	g, err := New(cfg, f.gateway.logger)
	if err != nil {
		t.Fatal(err)
	}
	rec := mcpRequest(t, g.Handler(), "Bearer "+alphaToken, "tools/call", map[string]any{"name": "alpha_tool", "arguments": map[string]any{"message": strings.Repeat("DO_NOT_LOG", 100)}})
	events := auditEvents(t, f.audit.String(), "http_request")
	if rec.Code < 400 || len(events) != 1 || events[0].Outcome != "request_too_large" || f.calls.Load() != 0 {
		t.Fatalf("oversized request not safely classified: %d %+v", rec.Code, events)
	}
	if strings.Contains(f.audit.String(), "DO_NOT_LOG") {
		t.Fatal("oversized body leaked into audit")
	}
}

func TestToolRegistrationPanicBecomesSafeError(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	err := registerTool(server, &mcp.Tool{Name: "demo", InputSchema: json.RawMessage(`{"type":"object","properties":{"x":{"type":"array","x-mcp-header":"DO_NOT_LOG"}}}`)},
		func(context.Context, *mcp.CallToolRequest, map[string]any) (*mcp.CallToolResult, any, error) {
			return nil, nil, nil
		})
	if err == nil || strings.Contains(err.Error(), "DO_NOT_LOG") {
		t.Fatalf("registration panic was not sanitized: %v", err)
	}
}

func TestInvalidTraceParentsAreReplaced(t *testing.T) {
	for _, parent := range []string{
		"", "DO_NOT_LOG_TRACE", "00-00000000000000000000000000000000-0123456789abcdef-01",
		"00-0123456789abcdef0123456789abcdef-0000000000000000-01",
		"00-0123456789ABCDEF0123456789ABCDEF-0123456789abcdef-01",
		"00-0123456789abcdef0123456789abcdef-0123456789abcdef-xx",
		"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01-extra",
	} {
		trace := requestTrace(parent)
		if !validTraceHex(trace.traceID, 32) || !validTraceHex(trace.spanID, 16) || trace.parentID != "" {
			t.Fatalf("invalid traceparent was trusted: %q", parent)
		}
	}
}
