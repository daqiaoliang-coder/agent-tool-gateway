package gateway

import (
	"context"
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
)

const (
	rotatedAlphaToken = "rotated-alpha-test-token-000000000"
	metricsToken      = "metrics-client-test-token-00000000"
	rotatedMetrics    = "rotated-metrics-test-token-0000000"
)

func credentialDocument() credentialSnapshot {
	return credentialSnapshot{
		Clients: map[string][]tokenCredential{
			"alpha": {{Token: alphaToken}},
			"beta":  {{Token: betaToken}},
		},
		Backends: map[string]tokenCredential{"alpha_tool": {Token: "backend-old-token"}},
		Metrics:  []tokenCredential{{Token: metricsToken}},
	}
}

func writeCredentials(t *testing.T, path string, document credentialSnapshot) {
	t.Helper()
	data, err := json.Marshal(document)
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

func newCredentialFixture(t *testing.T) *gatewayFixture {
	t.Helper()
	f := newGatewayFixture(t)
	f.config.CredentialsFile = filepath.Join(t.TempDir(), "credentials.json")
	for i := range f.config.Clients {
		f.config.Clients[i].TokenEnv = ""
	}
	f.config.Tools[0].BackendTokenRequired = true
	writeCredentials(t, f.config.CredentialsFile, credentialDocument())
	if err := f.config.Validate(); err != nil {
		t.Fatal(err)
	}
	g, err := New(f.config, f.gateway.logger)
	if err != nil {
		t.Fatal(err)
	}
	f.gateway, f.handler = g, g.Handler()
	return f
}

func TestCredentialTimeBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name       string
		credential tokenCredential
		want       bool
	}{
		{"unbounded", tokenCredential{}, true},
		{"not yet active", tokenCredential{NotBefore: now.Add(time.Nanosecond)}, false},
		{"activation boundary", tokenCredential{NotBefore: now}, true},
		{"before expiry", tokenCredential{ExpiresAt: now.Add(time.Nanosecond)}, true},
		{"expiry boundary", tokenCredential{ExpiresAt: now}, false},
		{"expired", tokenCredential{ExpiresAt: now.Add(-time.Nanosecond)}, false},
		{"revoked", tokenCredential{Revoked: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.credential.active(now); got != tc.want {
				t.Errorf("active() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClientCredentialRotationAndRevocation(t *testing.T) {
	f := newCredentialFixture(t)
	document := credentialDocument()
	document.Clients["alpha"] = append(document.Clients["alpha"], tokenCredential{Token: rotatedAlphaToken})
	writeCredentials(t, f.config.CredentialsFile, document)
	if _, ok := f.gateway.authenticate("Bearer " + rotatedAlphaToken); ok {
		t.Fatal("file changes became active without reload")
	}
	if err := f.gateway.ReloadCredentials(); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{alphaToken, rotatedAlphaToken} {
		rec := mcpRequest(t, f.handler, "Bearer "+token, "tools/list", map[string]any{})
		var result struct {
			Tools []struct{ Name string } `json:"tools"`
		}
		if err := json.Unmarshal(rpcResult(t, rec), &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Tools) != 2 || result.Tools[0].Name != "alpha_tool" || result.Tools[1].Name != "shared_tool" {
			t.Fatalf("rotation changed the client's tool permissions: %s", rec.Body.String())
		}
	}
	for _, state := range []tokenCredential{
		{Token: alphaToken, Revoked: true},
		{Token: alphaToken, ExpiresAt: time.Now().Add(-time.Minute)},
		{Token: alphaToken, NotBefore: time.Now().Add(time.Hour)},
	} {
		document.Clients["alpha"][0] = state
		writeCredentials(t, f.config.CredentialsFile, document)
		if err := f.gateway.ReloadCredentials(); err != nil {
			t.Fatal(err)
		}
		rec := mcpRequest(t, f.handler, "Bearer "+alphaToken, "tools/list", map[string]any{})
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("inactive token returned HTTP %d", rec.Code)
		}
		if _, ok := f.gateway.authenticate("Bearer " + rotatedAlphaToken); !ok {
			t.Error("rotation replacement stopped working")
		}
	}
	delete(document.Clients, "alpha")
	writeCredentials(t, f.config.CredentialsFile, document)
	if err := f.gateway.ReloadCredentials(); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.gateway.authenticate("Bearer " + rotatedAlphaToken); ok {
		t.Error("removed client credentials still authenticate")
	}
	if _, ok := f.gateway.authenticate("Bearer " + betaToken); !ok {
		t.Error("revoking alpha affected beta")
	}
}

func TestCredentialReloadRejectsInvalidDocumentsAtomically(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"malformed", `{"clients":`},
		{"null", `null`},
		{"wrong type", `[]`},
		{"trailing JSON", `{} {}`},
		{"unknown secret field", `{"secret-marker":"` + rotatedAlphaToken + `"}`},
		{"unknown client", `{"clients":{"secret-marker":[]}}`},
		{"unknown backend", `{"backends":{"secret-marker":{"token":"secret-marker"}}}`},
		{"anonymous backend", `{"backends":{"shared_tool":{"token":"secret-marker"}}}`},
		{"short token", `{"clients":{"alpha":[{"token":"secret-marker"}]}}`},
		{"invalid bearer", `{"clients":{"alpha":[{"token":"` + rotatedAlphaToken + `\r\nsecret-marker"}]}}`},
		{"bad timestamp", `{"clients":{"alpha":[{"token":"` + rotatedAlphaToken + `","expires_at":"secret-marker"}]}}`},
		{"inverted lifetime", `{"clients":{"alpha":[{"token":"` + rotatedAlphaToken + `","not_before":"2026-10-24T12:00:00Z","expires_at":"2026-10-24T11:00:00Z"}]}}`},
		{"duplicate field", `{"clients":{},"clients":{"alpha":[]}}`},
		{"duplicate nested field", `{"clients":{"alpha":[{"token":"` + rotatedAlphaToken + `","token":"secret-marker"}]}}`},
		{"case variant root", `{"clients":{},"Clients":{"alpha":[{"token":"` + rotatedAlphaToken + `"}]}}`},
		{"case variant revocation", `{"clients":{"alpha":[{"token":"` + rotatedAlphaToken + `","revoked":true,"Revoked":false}]}}`},
		{"case variant expiry", `{"clients":{"alpha":[{"token":"` + rotatedAlphaToken + `","Expires_At":"2026-10-24T11:00:00Z"}]}}`},
		{"case variant backend", `{"backends":{"alpha_tool":{"Token":"secret-marker"}}}`},
		{"case variant metrics", `{"metrics":[{"TOKEN":"` + rotatedMetrics + `"}]}`},
		{"null revocation", `{"clients":{"alpha":[{"token":"` + rotatedAlphaToken + `","revoked":null}]}}`},
		{"duplicate clients", `{"clients":{"alpha":[{"token":"` + rotatedAlphaToken + `"}],"beta":[{"token":"` + rotatedAlphaToken + `"}]}}`},
		{"metrics reuse", `{"clients":{"alpha":[{"token":"` + rotatedAlphaToken + `"}]},"metrics":[{"token":"` + rotatedAlphaToken + `"}]}`},
		{"backend reuse", `{"clients":{"alpha":[{"token":"` + rotatedAlphaToken + `"}]},"backends":{"alpha_tool":{"token":"` + rotatedAlphaToken + `"}}}`},
		{"invalid metrics after new client", `{"clients":{"alpha":[{"token":"` + rotatedAlphaToken + `"}]},"metrics":[{"token":"secret-marker"}]}`},
		{"oversized", strings.Repeat(" ", maxCredentialsBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCredentialFixture(t)
			before := f.gateway.secrets.Load()
			if err := os.WriteFile(f.config.CredentialsFile, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			err := f.gateway.ReloadCredentials()
			if err == nil {
				t.Fatal("invalid credentials accepted")
			}
			for _, secret := range []string{"secret-marker", rotatedAlphaToken, alphaToken, metricsToken} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("reload error leaked secret data")
				}
			}
			if f.gateway.secrets.Load() != before {
				t.Error("failed reload replaced the active snapshot")
			}
			if _, ok := f.gateway.authenticate("Bearer " + alphaToken); !ok {
				t.Error("failed reload revoked the previous token")
			}
			if _, ok := f.gateway.authenticate("Bearer " + rotatedAlphaToken); ok {
				t.Error("failed reload partially activated a replacement token")
			}
		})
	}
}

func TestCredentialIdentityKeysRemainCaseSensitive(t *testing.T) {
	f := newCredentialFixture(t)
	cfg := f.config
	client := cfg.Clients[0]
	client.ID, client.AllowedTools = "Alpha", []string{"Alpha_tool"}
	cfg.Clients = append(cfg.Clients, client)
	tool := cfg.Tools[0]
	tool.Name = "Alpha_tool"
	cfg.Tools = append(cfg.Tools, tool)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	document := credentialDocument()
	document.Clients["Alpha"] = []tokenCredential{{Token: rotatedAlphaToken}}
	document.Backends["Alpha_tool"] = tokenCredential{Token: "uppercase-backend-token"}
	writeCredentials(t, cfg.CredentialsFile, document)
	g, err := New(cfg, f.gateway.logger)
	if err != nil {
		t.Fatal(err)
	}
	for token, id := range map[string]string{alphaToken: "alpha", rotatedAlphaToken: "Alpha"} {
		identity, ok := g.authenticate("Bearer " + token)
		if !ok || identity.id != id {
			t.Errorf("case-sensitive client identity did not resolve to %s", id)
		}
	}
	if got := g.secrets.Load().Backends["Alpha_tool"].Token; got != "uppercase-backend-token" {
		t.Error("case-sensitive backend identity was not preserved")
	}
}

func TestCredentialFileAccessChecks(t *testing.T) {
	for _, mode := range []os.FileMode{0400, 0600, 0644, 0640} {
		t.Run(mode.String(), func(t *testing.T) {
			f := newCredentialFixture(t)
			if err := os.Chmod(f.config.CredentialsFile, mode); err != nil {
				t.Fatal(err)
			}
			err := f.gateway.ReloadCredentials()
			if (err == nil) != (mode == 0400 || mode == 0600) {
				t.Errorf("mode %o: unexpected reload result %v", mode, err)
			}
		})
	}
	f := newCredentialFixture(t)
	for _, path := range []string{t.TempDir(), filepath.Join(t.TempDir(), "missing")} {
		cfg := f.config
		cfg.CredentialsFile = path
		if _, err := New(cfg, nil); err == nil {
			t.Error("non-file credential source accepted")
		}
	}
}

func metricRequest(handler http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestMetricsCredentialRotation(t *testing.T) {
	f := newCredentialFixture(t)
	document := credentialDocument()
	document.Metrics = append(document.Metrics, tokenCredential{Token: rotatedMetrics})
	writeCredentials(t, f.config.CredentialsFile, document)
	if err := f.gateway.ReloadCredentials(); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{metricsToken, rotatedMetrics} {
		if got := metricRequest(f.handler, token).Code; got != http.StatusOK {
			t.Errorf("overlapping metrics token returned %d", got)
		}
		if _, ok := f.gateway.authenticate("Bearer " + token); ok {
			t.Error("metrics credential accepted as a client identity")
		}
	}
	if got := metricRequest(f.handler, alphaToken).Code; got != http.StatusUnauthorized {
		t.Errorf("client credential accepted for metrics: %d", got)
	}
	for _, credential := range []tokenCredential{
		{Token: metricsToken, Revoked: true},
		{Token: metricsToken, NotBefore: time.Now().Add(time.Hour)},
		{Token: metricsToken, ExpiresAt: time.Now().Add(-time.Hour)},
	} {
		document.Metrics[0] = credential
		writeCredentials(t, f.config.CredentialsFile, document)
		if err := f.gateway.ReloadCredentials(); err != nil {
			t.Fatal(err)
		}
		if got := metricRequest(f.handler, metricsToken).Code; got != http.StatusUnauthorized {
			t.Errorf("inactive metrics token returned %d", got)
		}
	}
	document.Metrics = nil
	writeCredentials(t, f.config.CredentialsFile, document)
	if err := f.gateway.ReloadCredentials(); err != nil {
		t.Fatal(err)
	}
	if got := metricRequest(f.handler, rotatedMetrics).Code; got != http.StatusNotFound {
		t.Errorf("disabled metrics returned %d", got)
	}
}

type recordingTransport func(*http.Request) (*http.Response, error)

func (f recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBackendCredentialRotationAndRequestSnapshot(t *testing.T) {
	f := newCredentialFixture(t)
	headers := make(chan string, 2)
	f.gateway.client.Transport = recordingTransport(func(r *http.Request) (*http.Response, error) {
		headers <- r.Header.Get("Authorization")
		return http.DefaultTransport.RoundTrip(r)
	})
	admitted, ok := f.gateway.authenticate("Bearer " + alphaToken)
	if !ok {
		t.Fatal("initial client failed authentication")
	}
	document := credentialDocument()
	document.Clients["alpha"] = []tokenCredential{{Token: rotatedAlphaToken}}
	document.Backends["alpha_tool"] = tokenCredential{Token: "backend-new-token"}
	writeCredentials(t, f.config.CredentialsFile, document)
	if err := f.gateway.ReloadCredentials(); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(t.Context(), identityContextKey{}, admitted)
	result, err := f.gateway.callTool(ctx, f.config.Tools[0], json.RawMessage(`{"message":"hello"}`))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("admitted call failed: %v %v", result, err)
	}
	select {
	case got := <-headers:
		if got != "Bearer backend-old-token" {
			t.Errorf("admitted call mixed credential generations: %q", got)
		}
	default:
		t.Fatal("admitted call did not reach the backend")
	}
	rec := mcpRequest(t, f.handler, "Bearer "+rotatedAlphaToken, "tools/call", map[string]any{"name": "alpha_tool", "arguments": map[string]any{"message": "hello"}})
	_ = rpcResult(t, rec)
	select {
	case got := <-headers:
		if got != "Bearer backend-new-token" {
			t.Errorf("new call used stale backend credentials: %q", got)
		}
	default:
		t.Fatal("new call did not reach the backend")
	}
	for _, secret := range []string{alphaToken, rotatedAlphaToken, "backend-old-token", "backend-new-token", metricsToken} {
		if strings.Contains(f.audit.String(), secret) || strings.Contains(rec.Body.String(), secret) {
			t.Error("credential appeared in audit or tool output")
		}
	}
}

func TestUnavailableBackendCredentialsNeverForward(t *testing.T) {
	f := newCredentialFixture(t)
	for _, credential := range []*tokenCredential{
		nil,
		{Token: "backend-token", Revoked: true},
		{Token: "backend-token", ExpiresAt: time.Now().Add(-time.Minute)},
		{Token: "backend-token", NotBefore: time.Now().Add(time.Hour)},
	} {
		document := credentialDocument()
		if credential == nil {
			delete(document.Backends, "alpha_tool")
		} else {
			document.Backends["alpha_tool"] = *credential
		}
		writeCredentials(t, f.config.CredentialsFile, document)
		if err := f.gateway.ReloadCredentials(); err != nil {
			t.Fatal(err)
		}
		rec := mcpRequest(t, f.handler, "Bearer "+alphaToken, "tools/call", map[string]any{"name": "alpha_tool", "arguments": map[string]any{"message": "hello"}})
		var result struct {
			IsError bool `json:"isError"`
		}
		if err := json.Unmarshal(rpcResult(t, rec), &result); err != nil {
			t.Fatal(err)
		}
		if !result.IsError || !strings.Contains(rec.Body.String(), "backend credential is unavailable") {
			t.Fatalf("unavailable backend credential was not rejected: %s", rec.Body.String())
		}
	}
	if got := f.calls.Load(); got != 0 {
		t.Errorf("unavailable credentials caused %d upstream calls", got)
	}
}

func TestCredentialReloadIsRaceFreeAndAtomic(t *testing.T) {
	f := newCredentialFixture(t)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 1000 {
				for _, token := range []string{alphaToken, rotatedAlphaToken} {
					identity, ok := f.gateway.authenticate("Bearer " + token)
					if !ok {
						continue
					}
					want := "backend-old-token"
					if token == rotatedAlphaToken {
						want = "backend-new-token"
					}
					if identity.id != "alpha" || identity.credentials.Backends["alpha_tool"].Token != want {
						t.Error("authentication observed mixed credential generations")
					}
				}
			}
		})
	}
	for i := range 20 {
		document := credentialDocument()
		if i%2 == 0 {
			document.Clients["alpha"] = []tokenCredential{{Token: rotatedAlphaToken}}
			document.Backends["alpha_tool"] = tokenCredential{Token: "backend-new-token"}
		}
		writeCredentials(t, f.config.CredentialsFile, document)
		if err := f.gateway.ReloadCredentials(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestEnvironmentCredentialsRemainStatic(t *testing.T) {
	f := newGatewayFixture(t)
	t.Setenv("ATG_TEST_ALPHA_TOKEN", rotatedAlphaToken)
	if err := f.gateway.ReloadCredentials(); err == nil {
		t.Fatal("environment-only gateway accepted online reload")
	}
	if _, ok := f.gateway.authenticate("Bearer " + alphaToken); !ok {
		t.Error("environment token changed without a restart")
	}
	if _, ok := f.gateway.authenticate("Bearer " + rotatedAlphaToken); ok {
		t.Error("new environment token became active without a restart")
	}
	f.config.Tools[0].BackendTokenEnv = "ATG_TEST_BACKEND_TOKEN"
	t.Setenv("ATG_TEST_BACKEND_TOKEN", "backend-env-token")
	g, err := New(f.config, f.gateway.logger)
	if err != nil {
		t.Fatal(err)
	}
	g.client.Transport = recordingTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer backend-env-token" {
			t.Error("environment backend token was not attached")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})
	rec := mcpRequest(t, g.Handler(), "Bearer "+rotatedAlphaToken, "tools/call", map[string]any{"name": "alpha_tool", "arguments": map[string]any{"message": "hello"}})
	_ = rpcResult(t, rec)
}
