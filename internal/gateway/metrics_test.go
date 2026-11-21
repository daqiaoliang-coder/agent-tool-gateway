package gateway

import (
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func scrapeMetrics(t *testing.T, m *metrics) (string, map[string]float64) {
	t.Helper()
	w := httptest.NewRecorder()
	m.serveHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if got := w.Header().Get("Content-Type"); got != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	return w.Body.String(), parseMetricSamples(t, w.Body.String())
}

func parseMetricSamples(t *testing.T, body string) map[string]float64 {
	t.Helper()
	samples := make(map[string]float64)
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		separator := strings.LastIndexByte(line, ' ')
		if separator < 0 {
			t.Fatalf("malformed metric line: %q", line)
		}
		key := line[:separator]
		parseMetricLabels(t, key)
		value, err := strconv.ParseFloat(line[separator+1:], 64)
		if err != nil {
			t.Fatalf("invalid metric value in %q: %v", line, err)
		}
		if _, duplicate := samples[key]; duplicate {
			t.Fatalf("duplicate series %q", key)
		}
		samples[key] = value
	}
	return samples
}

// Unlike strconv.Unquote, this accepts only Prometheus text-format escapes.
func parseMetricLabels(t *testing.T, key string) map[string]string {
	t.Helper()
	labels := make(map[string]string)
	start := strings.IndexByte(key, '{')
	if start < 0 {
		return labels
	}
	if !strings.HasSuffix(key, "}") {
		t.Fatalf("missing closing brace: %q", key)
	}
	input := key[start+1 : len(key)-1]
	for len(input) > 0 {
		equal := strings.IndexByte(input, '=')
		if equal <= 0 || equal+1 >= len(input) || input[equal+1] != '"' {
			t.Fatalf("invalid label in %q", key)
		}
		name := input[:equal]
		input = input[equal+2:]
		var value strings.Builder
		closed := false
		for len(input) > 0 {
			ch := input[0]
			input = input[1:]
			if ch == '"' {
				closed = true
				break
			}
			if ch == '\\' {
				if len(input) == 0 {
					t.Fatalf("unfinished escape in %q", key)
				}
				ch = input[0]
				input = input[1:]
				switch ch {
				case 'n':
					ch = '\n'
				case '\\', '"':
				default:
					t.Fatalf("unsupported Prometheus escape \\%c in %q", ch, key)
				}
			}
			value.WriteByte(ch)
		}
		if !closed {
			t.Fatalf("unterminated label in %q", key)
		}
		if _, duplicate := labels[name]; duplicate {
			t.Fatalf("duplicate label %q in %q", name, key)
		}
		labels[name] = value.String()
		if len(input) > 0 {
			if input[0] != ',' || len(input) == 1 {
				t.Fatalf("invalid label separator in %q", key)
			}
			input = input[1:]
		}
	}
	return labels
}

func requireMetric(t *testing.T, samples map[string]float64, key string, want float64) {
	t.Helper()
	got, ok := samples[key]
	if !ok {
		t.Errorf("missing series %s", key)
		return
	}
	if math.IsNaN(got) || math.IsInf(got, 0) || math.Abs(got-want) > 1e-9*math.Max(1, math.Abs(want)) {
		t.Errorf("%s = %g, want %g", key, got, want)
	}
}

func requireMetricHistogram(t *testing.T, samples map[string]float64, prefix, labels string, observations []time.Duration) {
	t.Helper()
	// Deliberately independent of the implementation's bucket table.
	bounds := []string{"0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5", "10", "30", "+Inf"}
	var sum float64
	for _, elapsed := range observations {
		sum += math.Max(0, elapsed.Seconds())
	}
	var previous float64
	for _, bound := range bounds {
		seconds, err := strconv.ParseFloat(bound, 64)
		if err != nil {
			t.Fatal(err)
		}
		var count float64
		for _, elapsed := range observations {
			if math.Max(0, elapsed.Seconds()) <= seconds {
				count++
			}
		}
		key := prefix + "_bucket{" + labels + ",le=\"" + bound + "\"}"
		requireMetric(t, samples, key, count)
		if samples[key] < previous {
			t.Errorf("non-cumulative bucket %s", key)
		}
		previous = samples[key]
	}
	requireMetric(t, samples, prefix+"_sum{"+labels+"}", sum)
	requireMetric(t, samples, prefix+"_count{"+labels+"}", float64(len(observations)))
}

func TestMetricsToolHistogram(t *testing.T) {
	m := newMetrics()
	observations := []time.Duration{-time.Second, 0, 31 * time.Second}
	for _, bound := range []time.Duration{
		5 * time.Millisecond, 10 * time.Millisecond, 25 * time.Millisecond,
		50 * time.Millisecond, 100 * time.Millisecond, 250 * time.Millisecond,
		500 * time.Millisecond, time.Second, 2500 * time.Millisecond,
		5 * time.Second, 10 * time.Second, 30 * time.Second,
	} {
		observations = append(observations, bound-time.Nanosecond, bound, bound+time.Nanosecond)
	}
	for _, elapsed := range observations {
		m.record("alpha", "success", elapsed)
	}
	m.record("beta", "upstream_error", 2*time.Second)
	body, samples := scrapeMetrics(t, m)
	requireMetric(t, samples, `agent_tool_gateway_tool_calls_total{tool="alpha",outcome="success"}`, float64(len(observations)))
	requireMetricHistogram(t, samples, "agent_tool_gateway_tool_call_duration_seconds", `tool="alpha"`, observations)
	requireMetricHistogram(t, samples, "agent_tool_gateway_tool_call_duration_seconds", `tool="beta"`, []time.Duration{2 * time.Second})
	if strings.Count(body, "# TYPE agent_tool_gateway_tool_call_duration_seconds histogram\n") != 1 {
		t.Error("missing histogram type declaration")
	}
	if strings.Contains(body, "# TYPE agent_tool_gateway_tool_call_duration_seconds_sum") || strings.Contains(body, "# TYPE agent_tool_gateway_tool_call_duration_seconds_count") {
		t.Error("histogram sum/count must not be declared as independent counters")
	}
}

func TestMetricsToolOutcomes(t *testing.T) {
	m := newMetrics()
	outcomes := []string{
		"success", "authentication_failed", "request_rejected", "protocol_error", "invalid_arguments",
		"unknown_tool", "tool_denied", "tool_disabled", "overloaded", "cancelled", "timeout",
		"upstream_error", "upstream_http_error", "response_too_large", "request_too_large",
		"backend_credential_unavailable", "internal_error",
	}
	var observations []time.Duration
	for _, outcome := range outcomes {
		m.record("alpha", outcome, time.Millisecond)
		observations = append(observations, time.Millisecond)
	}
	for i := 0; i < 100; i++ {
		m.record("alpha", fmt.Sprintf("untrusted-error-%d", i), time.Millisecond)
		observations = append(observations, time.Millisecond)
	}
	body, samples := scrapeMetrics(t, m)
	for _, outcome := range outcomes {
		requireMetric(t, samples, `agent_tool_gateway_tool_calls_total{tool="alpha",outcome="`+outcome+`"}`, 1)
	}
	requireMetric(t, samples, `agent_tool_gateway_tool_calls_total{tool="alpha",outcome="other"}`, 100)
	requireMetricHistogram(t, samples, "agent_tool_gateway_tool_call_duration_seconds", `tool="alpha"`, observations)
	if strings.Contains(body, "untrusted-error-") {
		t.Error("unbounded outcome leaked into metrics")
	}
}

func TestMetricsHTTPHistogramAndLabels(t *testing.T) {
	m := newMetrics()
	m.recordHTTP("/mcp", http.MethodPost, "success", 200, 5*time.Millisecond)
	m.recordHTTP("/mcp", http.MethodGet, "authentication_failed", 401, 10*time.Millisecond)
	m.recordHTTP("/mcp", http.MethodPost, "request_rejected", 400, 31*time.Second)
	m.recordHTTP("/metrics", http.MethodGet, "authentication_failed", 401, time.Millisecond)
	m.recordHTTP("/healthz", http.MethodHead, "success", 204, 0)
	m.recordHTTP("/readyz", http.MethodGet, "success", 204, 0)
	body, samples := scrapeMetrics(t, m)
	for _, labels := range []string{
		`route="/mcp",method="POST",outcome="success",status="200"`,
		`route="/mcp",method="GET",outcome="authentication_failed",status="401"`,
		`route="/mcp",method="POST",outcome="request_rejected",status="400"`,
		`route="/metrics",method="GET",outcome="authentication_failed",status="401"`,
		`route="/healthz",method="HEAD",outcome="success",status="204"`,
		`route="/readyz",method="GET",outcome="success",status="204"`,
	} {
		requireMetric(t, samples, "agent_tool_gateway_http_requests_total{"+labels+"}", 1)
	}
	requireMetricHistogram(t, samples, "agent_tool_gateway_http_request_duration_seconds", `route="/mcp"`, []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 31 * time.Second})
	requireMetricHistogram(t, samples, "agent_tool_gateway_http_request_duration_seconds", `route="/metrics"`, []time.Duration{time.Millisecond})
	if strings.Count(body, "# TYPE agent_tool_gateway_http_request_duration_seconds histogram\n") != 1 {
		t.Error("missing HTTP histogram type")
	}
	for key := range samples {
		if strings.HasPrefix(key, "agent_tool_gateway_http_request_duration_seconds") {
			labels := parseMetricLabels(t, key)
			for label := range labels {
				if label != "route" && label != "le" {
					t.Errorf("HTTP duration has extra label %q", label)
				}
			}
		}
	}
}

func TestMetricsHTTPCardinality(t *testing.T) {
	m := newMetrics()
	for i := 0; i < 3000; i++ {
		input := fmt.Sprintf("/private/%d?request_id=secret\"\\\n", i)
		m.recordHTTP(input, input, input, 600+i, time.Millisecond)
		m.recordHTTP(input, input, input, -i, time.Millisecond)
		m.recordReload(input, "success")
		m.recordReload("config", input)
	}
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"} {
		m.recordHTTP("/mcp", method, "success", 200, 0)
	}
	body, samples := scrapeMetrics(t, m)
	requireMetric(t, samples, `agent_tool_gateway_http_requests_total{route="[other]",method="[other]",outcome="other",status="0"}`, 6000)
	if strings.Contains(body, "private") || strings.Contains(body, "secret") || strings.Contains(body, "request_id") {
		t.Error("request-controlled label leaked into metrics")
	}
	var httpCount, reloadCount int
	for key := range samples {
		if strings.HasPrefix(key, "agent_tool_gateway_http_requests_total{") {
			httpCount++
			labels := parseMetricLabels(t, key)
			if len(labels) != 4 {
				t.Errorf("unexpected HTTP labels: %v", labels)
			}
		}
		if strings.HasPrefix(key, "agent_tool_gateway_reload_total{") {
			reloadCount++
			requireMetric(t, samples, key, 0)
		}
	}
	if httpCount != 10 || reloadCount != 4 {
		t.Errorf("series counts: HTTP=%d, reload=%d; want 10, 4", httpCount, reloadCount)
	}
	// Valid status codes stay distinct, but even arbitrary ints cannot create
	// more than the 500 valid codes plus the invalid-status sentinel.
	for status := -1000; status < 2000; status++ {
		m.recordHTTP("/metrics", "GET", "success", status, 0)
	}
	_, samples = scrapeMetrics(t, m)
	var statuses int
	for key := range samples {
		if strings.HasPrefix(key, `agent_tool_gateway_http_requests_total{route="/metrics"`) {
			statuses++
		}
	}
	if statuses != 501 {
		t.Errorf("status cardinality = %d, want 501", statuses)
	}
}

func TestMetricsLabelEscapingAndRevision(t *testing.T) {
	m := newMetrics()
	name := "line\n\"slash\\tab\treturn\rcontrol\x01雪"
	encoded := "\"line\\n\\\"slash\\\\tab\treturn\rcontrol\x01雪\""
	if got := metricLabel(name); got != encoded {
		t.Fatalf("escaped label = %q, want %q", got, encoded)
	}
	m.record(name, "success", time.Second)
	m.setRevision("old-revision")
	_, samples := scrapeMetrics(t, m)
	requireMetric(t, samples, `agent_tool_gateway_config_info{revision="old-revision"}`, 1)
	m.setRevision(name)
	body, samples := scrapeMetrics(t, m)
	requireMetric(t, samples, "agent_tool_gateway_tool_calls_total{tool="+encoded+`,outcome="success"}`, 1)
	requireMetric(t, samples, "agent_tool_gateway_config_info{revision="+encoded+"}", 1)
	var revisions int
	for key := range samples {
		if strings.HasPrefix(key, "agent_tool_gateway_config_info{") {
			revisions++
			if got := parseMetricLabels(t, key)["revision"]; got != name {
				t.Errorf("decoded revision = %q, want %q", got, name)
			}
		}
	}
	if revisions != 1 || strings.Contains(body, "old-revision") {
		t.Error("stale revision series retained")
	}
	second, _ := scrapeMetrics(t, m)
	if body != second {
		t.Error("unchanged metrics have nondeterministic exposition")
	}
	m.setRevision("")
	_, samples = scrapeMetrics(t, m)
	for key := range samples {
		if strings.HasPrefix(key, "agent_tool_gateway_config_info{") {
			t.Errorf("revision retained after clearing: %s", key)
		}
	}
}

func TestMetricsToolCardinalityAcrossRevisions(t *testing.T) {
	m := newMetrics()
	const extra = 50
	for i := 0; i < 1024+extra; i++ {
		m.setRevision(fmt.Sprintf("revision-%d", i))
		m.record(fmt.Sprintf("tool-%d", i), "success", time.Second)
	}
	// Existing tools are not routed to overflow once the cap is reached.
	m.record("tool-0", "tool_denied", 2*time.Second)
	m.record("another-tool", "overloaded", 3*time.Second)
	_, samples := scrapeMetrics(t, m)
	requireMetric(t, samples, `agent_tool_gateway_tool_calls_total{tool="tool-0",outcome="success"}`, 1)
	requireMetric(t, samples, `agent_tool_gateway_tool_calls_total{tool="tool-0",outcome="tool_denied"}`, 1)
	requireMetric(t, samples, `agent_tool_gateway_tool_calls_total{tool="[overflow]",outcome="success"}`, extra)
	requireMetric(t, samples, `agent_tool_gateway_tool_calls_total{tool="[overflow]",outcome="overloaded"}`, 1)
	observations := make([]time.Duration, extra)
	for i := range observations {
		observations[i] = time.Second
	}
	observations = append(observations, 3*time.Second)
	requireMetricHistogram(t, samples, "agent_tool_gateway_tool_call_duration_seconds", `tool="[overflow]"`, observations)
	var tools int
	for key := range samples {
		if strings.HasPrefix(key, "agent_tool_gateway_tool_call_duration_seconds_count{") {
			tools++
		}
	}
	if tools != 1025 {
		t.Errorf("historical tool cardinality = %d, want 1024 plus overflow", tools)
	}
}

func TestMetricsGaugesAndReloadHealth(t *testing.T) {
	m := newMetrics()
	_, samples := scrapeMetrics(t, m)
	requireMetric(t, samples, "agent_tool_gateway_in_flight", 0)
	requireMetric(t, samples, "agent_tool_gateway_concurrency_limit", 0)
	for _, kind := range []string{"config", "credentials"} {
		for _, outcome := range []string{"success", "rejected"} {
			requireMetric(t, samples, `agent_tool_gateway_reload_total{kind="`+kind+`",outcome="`+outcome+`"}`, 0)
		}
		requireMetric(t, samples, `agent_tool_gateway_last_reload_success_timestamp_seconds{kind="`+kind+`"}`, 0)
		requireMetric(t, samples, `agent_tool_gateway_last_reload_success{kind="`+kind+`"}`, 0)
	}
	m.setLimit(7)
	m.addInFlight(3)
	m.addInFlight(-1)
	_, samples = scrapeMetrics(t, m)
	requireMetric(t, samples, "agent_tool_gateway_in_flight", 2)
	requireMetric(t, samples, "agent_tool_gateway_concurrency_limit", 7)
	m.setLimit(4)
	m.addInFlight(-2)
	_, samples = scrapeMetrics(t, m)
	requireMetric(t, samples, "agent_tool_gateway_in_flight", 0)
	requireMetric(t, samples, "agent_tool_gateway_concurrency_limit", 4)

	for _, kind := range []string{"config", "credentials"} {
		t.Run(kind, func(t *testing.T) {
			labels := `{kind="` + kind + `"}`
			health := "agent_tool_gateway_last_reload_success" + labels
			timestamp := "agent_tool_gateway_last_reload_success_timestamp_seconds" + labels
			success := `agent_tool_gateway_reload_total{kind="` + kind + `",outcome="success"}`
			rejected := `agent_tool_gateway_reload_total{kind="` + kind + `",outcome="rejected"}`
			m.recordReload(kind, "rejected")
			_, samples := scrapeMetrics(t, m)
			requireMetric(t, samples, health, 0)
			requireMetric(t, samples, timestamp, 0)
			requireMetric(t, samples, rejected, 1)

			before := float64(time.Now().UnixNano()) / 1e9
			m.recordReload(kind, "success")
			after := float64(time.Now().UnixNano()) / 1e9
			_, samples = scrapeMetrics(t, m)
			requireMetric(t, samples, health, 1)
			requireMetric(t, samples, success, 1)
			lastSuccess := samples[timestamp]
			if lastSuccess < before || lastSuccess > after {
				t.Errorf("success timestamp %g not in [%g, %g]", lastSuccess, before, after)
			}
			m.recordReload(kind, "rejected")
			for i := 0; i < 2; i++ {
				_, samples = scrapeMetrics(t, m)
				requireMetric(t, samples, health, 0)
				requireMetric(t, samples, success, 1)
				requireMetric(t, samples, rejected, 2)
				if samples[timestamp] != lastSuccess {
					t.Error("rejection changed last-success timestamp")
				}
			}
			m.recordReload(kind, "success")
			_, samples = scrapeMetrics(t, m)
			requireMetric(t, samples, health, 1)
			requireMetric(t, samples, success, 2)
			requireMetric(t, samples, rejected, 2)
			if samples[timestamp] < lastSuccess {
				t.Error("success timestamp moved backwards")
			}
		})
	}
}

// A writer blocked in Header proves that even the first external writer call
// is outside the lock and that nested outcome maps were copied, not aliased.
type blockingMetricWriter struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
}

func (w *blockingMetricWriter) Header() http.Header {
	close(w.entered)
	<-w.release
	return w.ResponseRecorder.Header()
}

func TestMetricsSnapshotDoesNotHoldLockWhileWriting(t *testing.T) {
	m := newMetrics()
	m.record("alpha", "success", time.Second)
	m.recordHTTP("/mcp", "POST", "success", 200, time.Second)
	m.setRevision("before")
	m.setLimit(2)
	m.addInFlight(1)
	m.recordReload("config", "success")
	w := &blockingMetricWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.serveHTTP(w, nil)
	}()
	<-w.entered
	updated := make(chan struct{})
	go func() {
		defer close(updated)
		m.record("alpha", "success", time.Second)
		m.record("alpha", "tool_denied", time.Second)
		m.recordHTTP("/mcp", "POST", "success", 200, time.Second)
		m.setRevision("after")
		m.setLimit(3)
		m.addInFlight(-1)
		m.recordReload("config", "rejected")
	}()
	select {
	case <-updated:
	case <-time.After(5 * time.Second):
		close(w.release)
		<-done
		<-updated
		t.Fatal("metric updates blocked behind response writes")
	}
	close(w.release)
	<-done
	samples := parseMetricSamples(t, w.Body.String())
	requireMetric(t, samples, `agent_tool_gateway_tool_calls_total{tool="alpha",outcome="success"}`, 1)
	requireMetric(t, samples, `agent_tool_gateway_http_requests_total{route="/mcp",method="POST",outcome="success",status="200"}`, 1)
	requireMetric(t, samples, `agent_tool_gateway_config_info{revision="before"}`, 1)
	requireMetric(t, samples, "agent_tool_gateway_in_flight", 1)
	requireMetric(t, samples, "agent_tool_gateway_concurrency_limit", 2)
	requireMetric(t, samples, `agent_tool_gateway_last_reload_success{kind="config"}`, 1)
	if _, exists := samples[`agent_tool_gateway_tool_calls_total{tool="alpha",outcome="tool_denied"}`]; exists {
		t.Error("snapshot retained a mutable outcome map")
	}
	_, samples = scrapeMetrics(t, m)
	requireMetric(t, samples, `agent_tool_gateway_tool_calls_total{tool="alpha",outcome="success"}`, 2)
	requireMetric(t, samples, `agent_tool_gateway_config_info{revision="after"}`, 1)
	requireMetric(t, samples, "agent_tool_gateway_in_flight", 0)
}

func TestMetricsConcurrentRecordingAndScraping(t *testing.T) {
	m := newMetrics()
	const workers, iterations = 8, 100
	var wg sync.WaitGroup
	start := make(chan struct{})
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				m.addInFlight(1)
				m.record("alpha", "success", 5*time.Millisecond)
				m.record("alpha", "upstream_error", 10*time.Millisecond)
				m.recordHTTP("/mcp", "POST", "success", 200, 5*time.Millisecond)
				m.recordHTTP("/mcp", "GET", "authentication_failed", 401, 10*time.Millisecond)
				m.recordReload("config", "success")
				m.recordReload("credentials", "rejected")
				m.setLimit(worker + 1)
				m.setRevision(fmt.Sprintf("worker-%d-revision-%d", worker, i))
				m.addInFlight(-1)
			}
		}(worker)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 40; i++ {
				_, samples := scrapeMetrics(t, m)
				for _, test := range []struct {
					counter, histogram, labels string
				}{
					{"agent_tool_gateway_tool_calls_total", "agent_tool_gateway_tool_call_duration_seconds", `tool="alpha"`},
					{"agent_tool_gateway_http_requests_total", "agent_tool_gateway_http_request_duration_seconds", `route="/mcp"`},
				} {
					var total float64
					for key, value := range samples {
						if strings.HasPrefix(key, test.counter+"{") {
							total += value
						}
					}
					count := samples[test.histogram+"_count{"+test.labels+"}"]
					infinite := samples[test.histogram+"_bucket{"+test.labels+`,le="+Inf"}`]
					if total != count || total != infinite {
						t.Errorf("inconsistent snapshot: %s total=%g, count=%g, +Inf=%g", test.counter, total, count, infinite)
					}
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	_, samples := scrapeMetrics(t, m)
	const calls = workers * iterations
	requireMetric(t, samples, `agent_tool_gateway_tool_calls_total{tool="alpha",outcome="success"}`, calls)
	requireMetric(t, samples, `agent_tool_gateway_tool_calls_total{tool="alpha",outcome="upstream_error"}`, calls)
	requireMetric(t, samples, `agent_tool_gateway_http_requests_total{route="/mcp",method="POST",outcome="success",status="200"}`, calls)
	requireMetric(t, samples, `agent_tool_gateway_reload_total{kind="config",outcome="success"}`, calls)
	requireMetric(t, samples, `agent_tool_gateway_reload_total{kind="credentials",outcome="rejected"}`, calls)
	requireMetric(t, samples, `agent_tool_gateway_last_reload_success{kind="config"}`, 1)
	requireMetric(t, samples, `agent_tool_gateway_last_reload_success{kind="credentials"}`, 0)
	requireMetric(t, samples, "agent_tool_gateway_in_flight", 0)
	observations := make([]time.Duration, 0, calls*2)
	for i := 0; i < calls; i++ {
		observations = append(observations, 5*time.Millisecond, 10*time.Millisecond)
	}
	requireMetricHistogram(t, samples, "agent_tool_gateway_tool_call_duration_seconds", `tool="alpha"`, observations)
	requireMetricHistogram(t, samples, "agent_tool_gateway_http_request_duration_seconds", `route="/mcp"`, observations)
}
