package gateway

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxMetricTools = 1024

var metricDurationBounds = [...]time.Duration{
	5 * time.Millisecond, 10 * time.Millisecond, 25 * time.Millisecond,
	50 * time.Millisecond, 100 * time.Millisecond, 250 * time.Millisecond,
	500 * time.Millisecond, time.Second, 2500 * time.Millisecond,
	5 * time.Second, 10 * time.Second, 30 * time.Second,
}

type durationMetric struct {
	Buckets [len(metricDurationBounds)]uint64
	Count   uint64
	Seconds float64
}

func (d *durationMetric) observe(elapsed time.Duration) {
	// Durations cannot be negative; keep the sum monotonic even for a bad caller.
	if elapsed < 0 {
		elapsed = 0
	}
	for i, bound := range metricDurationBounds {
		if elapsed <= bound {
			d.Buckets[i]++
		}
	}
	d.Count++
	d.Seconds += elapsed.Seconds()
}

type toolMetric struct {
	Outcomes map[string]uint64
	Duration durationMetric
}

type httpMetricKey struct {
	Route   string
	Method  string
	Outcome string
	Status  int
}

type reloadMetric struct {
	Success              uint64
	Rejected             uint64
	LastSuccessTimestamp float64
	LastSuccess          int
}

type metrics struct {
	mu            sync.Mutex
	tools         map[string]toolMetric
	httpRequests  map[httpMetricKey]uint64
	httpDurations map[string]durationMetric
	reloads       map[string]reloadMetric
	revision      string
	limit         int
	inFlight      int64
}

func newMetrics() *metrics {
	return &metrics{
		tools:         make(map[string]toolMetric),
		httpRequests:  make(map[httpMetricKey]uint64),
		httpDurations: make(map[string]durationMetric),
		// Export both outcomes and health gauges even before the first reload.
		reloads: map[string]reloadMetric{"config": {}, "credentials": {}},
	}
}

// Never use arbitrary request paths, method names or error text as labels.
func metricOutcome(outcome string) string {
	switch outcome {
	case "success", "authentication_failed", "request_rejected", "protocol_error", "invalid_arguments",
		"unknown_tool", "tool_denied", "tool_disabled", "overloaded", "cancelled", "timeout",
		"upstream_error", "upstream_http_error", "response_too_large", "request_too_large",
		"backend_credential_unavailable", "internal_error":
		return outcome
	default:
		return "other"
	}
}

func metricRoute(route string) string {
	switch route {
	case "/mcp", "/metrics", "/healthz", "/readyz":
		return route
	default:
		return "[other]"
	}
}

func metricHTTPMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace,
		http.MethodPatch:
		return method
	default:
		return "[other]"
	}
}

func (m *metrics) record(name string, outcome string, elapsed time.Duration) {
	outcome = metricOutcome(outcome)
	m.mu.Lock()
	defer m.mu.Unlock()
	// Configured tool names need a lifetime cap across configuration generations.
	if _, exists := m.tools[name]; !exists && len(m.tools) >= maxMetricTools {
		name = "[overflow]"
	}
	value := m.tools[name]
	if value.Outcomes == nil {
		value.Outcomes = make(map[string]uint64)
	}
	value.Outcomes[outcome]++
	value.Duration.observe(elapsed)
	m.tools[name] = value
}

func (m *metrics) recordHTTP(route, method, outcome string, status int, elapsed time.Duration) {
	route = metricRoute(route)
	method = metricHTTPMethod(method)
	outcome = metricOutcome(outcome)
	if status < 100 || status > 599 {
		status = 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.httpRequests[httpMetricKey{Route: route, Method: method, Outcome: outcome, Status: status}]++
	value := m.httpDurations[route]
	value.observe(elapsed)
	m.httpDurations[route] = value
}

func (m *metrics) recordReload(kind, outcome string) {
	if (kind != "config" && kind != "credentials") || (outcome != "success" && outcome != "rejected") {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	value := m.reloads[kind]
	if outcome == "success" {
		value.Success++
		value.LastSuccess = 1
		value.LastSuccessTimestamp = float64(time.Now().UnixNano()) / 1e9
	} else {
		value.Rejected++
		value.LastSuccess = 0
	}
	m.reloads[kind] = value
}

func (m *metrics) setRevision(revision string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revision = revision
}

func (m *metrics) setLimit(limit int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.limit = limit
}

func (m *metrics) addInFlight(delta int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inFlight += delta
}

// Go's %q produces escapes unsupported by Prometheus text labels.
var metricLabelEscaper = strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n")

func metricLabel(value string) string {
	return "\"" + metricLabelEscaper.Replace(value) + "\""
}

func writeMetricHeader(w io.Writer, name, help, kind string) {
	_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
}

func writeDurationMetric(w io.Writer, name, labels string, value durationMetric) {
	for i, bound := range metricDurationBounds {
		_, _ = fmt.Fprintf(w, "%s_bucket{%s,le=\"%g\"} %d\n", name, labels, bound.Seconds(), value.Buckets[i])
	}
	_, _ = fmt.Fprintf(w, "%s_bucket{%s,le=\"+Inf\"} %d\n", name, labels, value.Count)
	_, _ = fmt.Fprintf(w, "%s_sum{%s} %g\n", name, labels, value.Seconds)
	_, _ = fmt.Fprintf(w, "%s_count{%s} %d\n", name, labels, value.Count)
}

func (m *metrics) serveHTTP(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	tools := make(map[string]toolMetric, len(m.tools))
	for name, value := range m.tools {
		outcomes := make(map[string]uint64, len(value.Outcomes))
		for outcome, count := range value.Outcomes {
			outcomes[outcome] = count
		}
		value.Outcomes = outcomes
		tools[name] = value
	}
	httpRequests := make(map[httpMetricKey]uint64, len(m.httpRequests))
	for key, count := range m.httpRequests {
		httpRequests[key] = count
	}
	httpDurations := make(map[string]durationMetric, len(m.httpDurations))
	for route, value := range m.httpDurations {
		httpDurations[route] = value
	}
	reloads := make(map[string]reloadMetric, len(m.reloads))
	for kind, value := range m.reloads {
		reloads[kind] = value
	}
	revision, limit, inFlight := m.revision, m.limit, m.inFlight
	m.mu.Unlock()

	// No response writer calls (including Header) happen while holding the lock.
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeMetricHeader(w, "agent_tool_gateway_tool_calls_total", "MCP tool calls by outcome.", "counter")
	names := make([]string, 0, len(tools))
	for name := range tools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		outcomes := make([]string, 0, len(tools[name].Outcomes))
		for outcome := range tools[name].Outcomes {
			outcomes = append(outcomes, outcome)
		}
		sort.Strings(outcomes)
		for _, outcome := range outcomes {
			_, _ = fmt.Fprintf(w, "agent_tool_gateway_tool_calls_total{tool=%s,outcome=%s} %d\n", metricLabel(name), metricLabel(outcome), tools[name].Outcomes[outcome])
		}
	}
	writeMetricHeader(w, "agent_tool_gateway_tool_call_duration_seconds", "MCP tool call duration in seconds.", "histogram")
	for _, name := range names {
		writeDurationMetric(w, "agent_tool_gateway_tool_call_duration_seconds", "tool="+metricLabel(name), tools[name].Duration)
	}

	writeMetricHeader(w, "agent_tool_gateway_http_requests_total", "HTTP requests by route, method, outcome, and status.", "counter")
	keys := make([]httpMetricKey, 0, len(httpRequests))
	for key := range httpRequests {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Route != b.Route {
			return a.Route < b.Route
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		if a.Outcome != b.Outcome {
			return a.Outcome < b.Outcome
		}
		return a.Status < b.Status
	})
	for _, key := range keys {
		_, _ = fmt.Fprintf(w, "agent_tool_gateway_http_requests_total{route=%s,method=%s,outcome=%s,status=\"%d\"} %d\n", metricLabel(key.Route), metricLabel(key.Method), metricLabel(key.Outcome), key.Status, httpRequests[key])
	}
	writeMetricHeader(w, "agent_tool_gateway_http_request_duration_seconds", "HTTP request duration in seconds by route.", "histogram")
	routes := make([]string, 0, len(httpDurations))
	for route := range httpDurations {
		routes = append(routes, route)
	}
	sort.Strings(routes)
	for _, route := range routes {
		writeDurationMetric(w, "agent_tool_gateway_http_request_duration_seconds", "route="+metricLabel(route), httpDurations[route])
	}

	writeMetricHeader(w, "agent_tool_gateway_in_flight", "Currently executing tool calls.", "gauge")
	_, _ = fmt.Fprintf(w, "agent_tool_gateway_in_flight %d\n", inFlight)
	writeMetricHeader(w, "agent_tool_gateway_concurrency_limit", "Configured tool call concurrency limit.", "gauge")
	_, _ = fmt.Fprintf(w, "agent_tool_gateway_concurrency_limit %d\n", limit)
	writeMetricHeader(w, "agent_tool_gateway_reload_total", "Reload attempts by kind and outcome.", "counter")
	for _, kind := range []string{"config", "credentials"} {
		_, _ = fmt.Fprintf(w, "agent_tool_gateway_reload_total{kind=%s,outcome=\"success\"} %d\n", metricLabel(kind), reloads[kind].Success)
		_, _ = fmt.Fprintf(w, "agent_tool_gateway_reload_total{kind=%s,outcome=\"rejected\"} %d\n", metricLabel(kind), reloads[kind].Rejected)
	}
	writeMetricHeader(w, "agent_tool_gateway_last_reload_success_timestamp_seconds", "Unix timestamp of the last successful reload, or zero if none.", "gauge")
	for _, kind := range []string{"config", "credentials"} {
		_, _ = fmt.Fprintf(w, "agent_tool_gateway_last_reload_success_timestamp_seconds{kind=%s} %g\n", metricLabel(kind), reloads[kind].LastSuccessTimestamp)
	}
	writeMetricHeader(w, "agent_tool_gateway_last_reload_success", "Whether the last reload succeeded (zero before any reload).", "gauge")
	for _, kind := range []string{"config", "credentials"} {
		_, _ = fmt.Fprintf(w, "agent_tool_gateway_last_reload_success{kind=%s} %d\n", metricLabel(kind), reloads[kind].LastSuccess)
	}
	writeMetricHeader(w, "agent_tool_gateway_config_info", "Currently active configuration revision.", "gauge")
	if revision != "" {
		_, _ = fmt.Fprintf(w, "agent_tool_gateway_config_info{revision=%s} 1\n", metricLabel(revision))
	}
}
