package gateway

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

type toolMetric struct {
	Success int64
	Errors  int64
	Seconds float64
}

type metrics struct {
	mu    sync.Mutex
	tools map[string]toolMetric
}

func newMetrics() *metrics {
	return &metrics{tools: make(map[string]toolMetric)}
}

func (m *metrics) record(name string, success bool, elapsed time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value := m.tools[name]
	if success {
		value.Success++
	} else {
		value.Errors++
	}
	value.Seconds += elapsed.Seconds()
	m.tools[name] = value
}

func (m *metrics) serveHTTP(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	snapshot := make(map[string]toolMetric, len(m.tools))
	for name, value := range m.tools {
		snapshot[name] = value
	}
	m.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintln(w, "# HELP agent_tool_gateway_tool_calls_total MCP tool calls by outcome.")
	_, _ = fmt.Fprintln(w, "# TYPE agent_tool_gateway_tool_calls_total counter")
	_, _ = fmt.Fprintln(w, "# HELP agent_tool_gateway_tool_call_duration_seconds_sum Total tool call duration in seconds.")
	_, _ = fmt.Fprintln(w, "# TYPE agent_tool_gateway_tool_call_duration_seconds_sum counter")
	_, _ = fmt.Fprintln(w, "# HELP agent_tool_gateway_tool_call_duration_seconds_count Number of tool calls included in duration sum.")
	_, _ = fmt.Fprintln(w, "# TYPE agent_tool_gateway_tool_call_duration_seconds_count counter")
	names := make([]string, 0, len(snapshot))
	for name := range snapshot {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := snapshot[name]
		_, _ = fmt.Fprintf(w, "agent_tool_gateway_tool_calls_total{tool=%q,outcome=\"success\"} %d\n", name, value.Success)
		_, _ = fmt.Fprintf(w, "agent_tool_gateway_tool_calls_total{tool=%q,outcome=\"error\"} %d\n", name, value.Errors)
		_, _ = fmt.Fprintf(w, "agent_tool_gateway_tool_call_duration_seconds_sum{tool=%q} %g\n", name, value.Seconds)
		_, _ = fmt.Fprintf(w, "agent_tool_gateway_tool_call_duration_seconds_count{tool=%q} %d\n", name, value.Success+value.Errors)
	}
}
