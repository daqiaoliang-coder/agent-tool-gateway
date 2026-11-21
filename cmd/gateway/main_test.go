package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/daqiaoliang-coder/agent-tool-gateway/internal/config"
)

const (
	gatewayHelperConfigEnv = "GATEWAY_MAIN_TEST_HELPER_CONFIG"
	gatewayHelperCheckEnv  = "GATEWAY_MAIN_TEST_HELPER_CHECK"
)

// Reuse the current test executable while exercising the real main signal loop.
func TestGatewayMainHelperProcess(t *testing.T) {
	configPath := os.Getenv(gatewayHelperConfigEnv)
	if configPath == "" {
		return
	}
	os.Args = []string{os.Args[0], "-config", configPath}
	if os.Getenv(gatewayHelperCheckEnv) == "1" {
		os.Args = append(os.Args, "-check")
	}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	main()
	os.Exit(0)
}

type gatewayProcessLogs struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	changed chan struct{}
}

func (l *gatewayProcessLogs) Write(p []byte) (int, error) {
	l.mu.Lock()
	n, err := l.buffer.Write(p)
	l.mu.Unlock()
	select {
	case l.changed <- struct{}{}:
	default:
	}
	return n, err
}

func (l *gatewayProcessLogs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buffer.String()
}

func (l *gatewayProcessLogs) messageRevisions(message string) []string {
	var revisions []string
	for _, line := range strings.Split(l.String(), "\n") {
		var entry struct {
			Message  string `json:"msg"`
			Revision string `json:"config_revision"`
		}
		if json.Unmarshal([]byte(line), &entry) == nil && entry.Message == message {
			revisions = append(revisions, entry.Revision)
		}
	}
	return revisions
}

func (l *gatewayProcessLogs) messageCount(message string) int {
	return len(l.messageRevisions(message))
}

type gatewayMainProcess struct {
	cmd     *exec.Cmd
	logs    *gatewayProcessLogs
	done    chan struct{}
	waitErr error // Published by closing done, after output has drained.
}

func startGatewayMainProcess(t *testing.T, configPath string, check bool) *gatewayMainProcess {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := &gatewayMainProcess{
		cmd:  exec.Command(executable, "-test.run=^TestGatewayMainHelperProcess$"),
		logs: &gatewayProcessLogs{changed: make(chan struct{}, 1)},
		done: make(chan struct{}),
	}
	checkValue := ""
	if check {
		checkValue = "1"
	}
	p.cmd.Env = append(os.Environ(), gatewayHelperConfigEnv+"="+configPath, gatewayHelperCheckEnv+"="+checkValue)
	p.cmd.Stdout, p.cmd.Stderr = p.logs, p.logs
	p.cmd.WaitDelay = 2 * time.Second
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		p.waitErr = p.cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		select {
		case <-p.done:
			return
		default:
		}
		// Only kill this test's helper, and only if it has not stopped already.
		_ = p.cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			t.Error("gateway helper did not exit during cleanup")
		}
	})
	return p
}

func (p *gatewayMainProcess) waitForLog(t *testing.T, message string, wantCount int) {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for p.logs.messageCount(message) < wantCount {
		select {
		case <-p.logs.changed:
		case <-p.done:
			t.Fatalf("gateway exited while waiting for %q: %v", message, p.waitErr)
		case <-timer.C:
			t.Fatalf("timed out waiting for occurrence %d of %q", wantCount, message)
		}
	}
}

func (p *gatewayMainProcess) waitForExit(t *testing.T) error {
	t.Helper()
	select {
	case <-p.done:
		return p.waitErr
	case <-time.After(15 * time.Second):
		t.Fatal("gateway helper did not exit")
		return nil
	}
}

func (p *gatewayMainProcess) signal(t *testing.T, signal syscall.Signal) {
	t.Helper()
	if err := p.cmd.Process.Signal(signal); err != nil {
		t.Fatal(err)
	}
}

func (p *gatewayMainProcess) shutdown(t *testing.T) {
	t.Helper()
	p.signal(t, syscall.SIGTERM)
	if err := p.waitForExit(t); err != nil {
		t.Fatalf("SIGTERM should shut down normally: %v", err)
	}
}

func (p *gatewayMainProcess) waitForReady(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	p.waitForLog(t, "agent tool gateway listening", 1)
	// The startup log precedes socket binding, so readiness needs a separate probe.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/healthz", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent {
				return
			}
		}
		select {
		case <-p.done:
			t.Fatalf("gateway exited before becoming healthy: %v", p.waitErr)
		case <-ctx.Done():
			t.Fatalf("gateway health probe timed out: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func gatewayMainTestConfig(addr, credentialsPath string) config.Config {
	return config.Config{
		ListenAddr: addr, CredentialsFile: credentialsPath,
		Clients: []config.Client{{ID: "demo", AllowedTools: []string{"demo_tool"}}},
		Tools: []config.Tool{{
			Name: "demo_tool", Description: "DO_NOT_LOG_FULL_CONFIGURATION", Method: "GET",
			BackendTokenRequired: true,
			Endpoint:             "http://" + addr + "/unused-backend", InputSchema: json.RawMessage(`{"type":"object"}`),
		}},
	}
}

func marshalGatewayMainConfig(t *testing.T, cfg config.Config) []byte {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func replaceGatewayMainFile(t *testing.T, path string, data []byte) {
	t.Helper()
	staged := path + ".next"
	if err := os.WriteFile(staged, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, path); err != nil {
		t.Fatal(err)
	}
}

func reserveGatewayMainListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func assertGatewayRevision(t *testing.T, revision string) {
	t.Helper()
	decoded, err := hex.DecodeString(revision)
	if err != nil || len(decoded) != sha256.Size {
		t.Fatalf("config revision must be a hex SHA-256 digest, got %q", revision)
	}
}

func assertGatewayLogRevisions(t *testing.T, logs *gatewayProcessLogs, message string, want ...string) {
	t.Helper()
	got := logs.messageRevisions(message)
	if len(got) != len(want) {
		t.Fatalf("%q log count = %d, want %d", message, len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%q occurrence %d revision = %q, want %q", message, i+1, got[i], want[i])
		}
	}
}

func assertGatewayLogsSafe(t *testing.T, logs *gatewayProcessLogs, sensitive ...string) {
	t.Helper()
	for i, value := range append(sensitive, "DO_NOT_LOG_FULL_CONFIGURATION", "panic:", "fatal error:") {
		if strings.Contains(logs.String(), value) {
			t.Errorf("gateway logs contain forbidden value %d", i+1)
		}
	}
}

func TestMainCheckWithoutCredentialsOrListener(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "missing-credentials.json")
	configPath := filepath.Join(dir, "gateway.json")
	// Keep the configured port occupied: -check must succeed without binding it.
	listener := reserveGatewayMainListener(t)
	cfg := gatewayMainTestConfig(listener.Addr().String(), secretPath)
	replaceGatewayMainFile(t, configPath, marshalGatewayMainConfig(t, cfg))
	process := startGatewayMainProcess(t, configPath, true)
	if err := process.waitForExit(t); err != nil {
		t.Fatalf("-check should succeed without credentials or a free port: %v", err)
	}
	revisions := process.logs.messageRevisions("configuration valid")
	if len(revisions) != 1 {
		t.Fatalf("configuration valid log count = %d, want 1", len(revisions))
	}
	assertGatewayRevision(t, revisions[0])
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if revisions[0] != cfg.Revision() {
		t.Error("-check did not log the validated configuration revision")
	}
	if _, err := os.Stat(secretPath); !os.IsNotExist(err) {
		t.Fatalf("credential file should remain absent, stat error = %v", err)
	}
	for _, message := range []string{"agent tool gateway listening", "configuration activated", "initialize gateway"} {
		assertGatewayLogRevisions(t, process.logs, message)
	}
	assertGatewayLogsSafe(t, process.logs, secretPath)
}

func TestMainCheckRejectsInvalidSchemaSafely(t *testing.T) {
	const (
		token          = "check-test-token-0123456789-abcdefghijklmnopqrstuvwxyz"
		maliciousField = "DO_NOT_LOG_SCHEMA_FIELD"
		maliciousValue = "DO_NOT_LOG_SCHEMA_VALUE"
	)
	for _, tc := range []struct {
		name, schema string
	}{
		{"unresolved reference", fmt.Sprintf(`{"type":"object","properties":{%q:{"$ref":%q}}}`, maliciousField, "#/$defs/"+maliciousValue)},
		{"invalid default", fmt.Sprintf(`{"type":"object","properties":{%q:{"type":"integer","default":%q}}}`, maliciousField, maliciousValue)},
		{"invalid SDK annotation", fmt.Sprintf(`{"type":"object","properties":{%q:{"type":"array","x-mcp-header":%q}}}`, maliciousField, maliciousValue)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			secretPath := filepath.Join(dir, "credentials.json")
			configPath := filepath.Join(dir, "gateway.json")
			listener := reserveGatewayMainListener(t)
			cfg := gatewayMainTestConfig(listener.Addr().String(), secretPath)
			cfg.Tools[0].InputSchema = json.RawMessage(tc.schema)
			replaceGatewayMainFile(t, configPath, marshalGatewayMainConfig(t, cfg))
			replaceGatewayMainFile(t, secretPath, []byte(fmt.Sprintf(`{"clients":{"demo":[{"token":%q}]},"backends":{},"metrics":[]}`, token)))
			process := startGatewayMainProcess(t, configPath, true)
			err := process.waitForExit(t)
			if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
				t.Fatalf("invalid schema should exit with status 1, got %v", err)
			}
			if process.logs.messageCount("load configuration") != 1 {
				t.Error("invalid schema was not rejected during configuration validation")
			}
			for _, message := range []string{"configuration valid", "configuration activated", "agent tool gateway listening", "initialize gateway"} {
				assertGatewayLogRevisions(t, process.logs, message)
			}
			assertGatewayLogsSafe(t, process.logs, token, maliciousField, maliciousValue)
		})
	}
}

func TestMainConfigReloadSignals(t *testing.T) {
	const (
		token          = "config-test-token-0123456789-abcdefghijklmnopqrstuvwxyz"
		backendToken   = "backend-test-token-0123456789-abcdefghijklmnopqrstuvwxyz"
		maliciousField = "DO_NOT_LOG_CONFIG_FIELD"
		maliciousValue = "DO_NOT_LOG_CONFIG_VALUE"
		reloadMessage  = "configuration reloaded"
		rejectMessage  = "configuration reload rejected; previous configuration remains active"
	)
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "credentials.json")
	configPath := filepath.Join(dir, "gateway.json")
	credentials := []byte(fmt.Sprintf(`{"clients":{"demo":[{"token":%q}]},"backends":{"demo_tool":{"token":%q}},"metrics":[]}`, token, backendToken))
	replaceGatewayMainFile(t, secretPath, credentials)
	listener := reserveGatewayMainListener(t)
	addr := listener.Addr().String()
	baseURL := "http://" + addr
	originalConfig := marshalGatewayMainConfig(t, gatewayMainTestConfig(addr, secretPath))
	replaceGatewayMainFile(t, configPath, originalConfig)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	process := startGatewayMainProcess(t, configPath, false)
	transport := &http.Transport{}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	process.waitForReady(t, client, baseURL)

	type rpcResponse struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		Result struct {
			Tools []struct {
				Name string            `json:"name"`
				Meta map[string]string `json:"_meta"`
			} `json:"tools"`
		} `json:"result"`
	}
	request := func(method, params string) (string, rpcResponse) {
		t.Helper()
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}`, method, params)
		req, err := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s request: %v", method, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s HTTP status = %d, want 200", method, resp.StatusCode)
		}
		var rpc rpcResponse
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rpc); err != nil {
			t.Fatalf("decode %s response: %v", method, err)
		}
		if rpc.JSONRPC != "2.0" || rpc.ID != 1 {
			t.Fatalf("%s returned an invalid JSON-RPC envelope", method)
		}
		revision := resp.Header.Get("X-Config-Revision")
		assertGatewayRevision(t, revision)
		return revision, rpc
	}
	assertToolsList := func(stage, wantRevision string, visible bool) string {
		t.Helper()
		revision, rpc := request("tools/list", `{}`)
		if wantRevision != "" && revision != wantRevision {
			t.Fatalf("%s: revision = %q, want %q", stage, revision, wantRevision)
		}
		if rpc.Error != nil {
			t.Fatalf("%s: tools/list returned an RPC error", stage)
		}
		tools := rpc.Result.Tools
		if !visible {
			if len(tools) != 0 {
				t.Fatalf("%s: disabled tool remains discoverable", stage)
			}
		} else if len(tools) != 1 || tools[0].Name != "demo_tool" || tools[0].Meta["gateway/version"] != "1" || tools[0].Meta["gateway/state"] != "active" {
			t.Fatalf("%s: expected demo_tool with default version 1 and active state", stage)
		}
		return revision
	}
	assertDisabledCall := func(wantRevision string) {
		t.Helper()
		revision, rpc := request("tools/call", `{"name":"demo_tool","arguments":{}}`)
		if revision != wantRevision {
			t.Fatalf("disabled call revision = %q, want %q", revision, wantRevision)
		}
		if rpc.Error == nil || rpc.Error.Code != -32602 || rpc.Error.Message != `unknown tool "demo_tool"` {
			t.Fatal("disabled tool call must be rejected as an unknown tool")
		}
	}

	originalRevision := assertToolsList("startup", "", true)
	assertGatewayLogRevisions(t, process.logs, "configuration activated", originalRevision)
	disabledConfig := gatewayMainTestConfig(addr, secretPath)
	disabledConfig.Tools[0].State = "disabled"
	replaceGatewayMainFile(t, configPath, marshalGatewayMainConfig(t, disabledConfig))
	assertToolsList("replacement before SIGUSR1", originalRevision, true)
	process.signal(t, syscall.SIGUSR1)
	process.waitForLog(t, reloadMessage, 1)
	disabledRevision := assertToolsList("after SIGUSR1", "", false)
	if disabledRevision == originalRevision {
		t.Fatal("successful config release did not change the revision")
	}
	assertGatewayLogRevisions(t, process.logs, reloadMessage, disabledRevision)
	assertDisabledCall(disabledRevision)

	// Every rejected candidate would re-enable the tool if partially published.
	rejections := []struct {
		name               string
		edit               func(*config.Config)
		data               []byte
		credentialData     []byte
		missingCredentials bool
	}{
		{name: "bad JSON", data: []byte(fmt.Sprintf(`{%q:%q,`, maliciousField, maliciousValue))},
		{name: "unknown config field", data: []byte(fmt.Sprintf(`{%q:%q}`, maliciousField, maliciousValue))},
		{name: "invalid schema", edit: func(c *config.Config) {
			c.Tools[0].InputSchema = json.RawMessage(fmt.Sprintf(`{"type":"object","properties":{%q:{"type":"integer","default":%q}}}`, maliciousField, maliciousValue))
		}},
		{name: "missing credentials", missingCredentials: true},
		{name: "invalid credentials", credentialData: []byte(fmt.Sprintf(`{"clients":{"demo":[{"token":%q}]},%q:%q}`, token, maliciousField, maliciousValue))},
		{name: "listen address requires restart", edit: func(c *config.Config) { c.ListenAddr = "127.0.0.1:0" }},
		{name: "concurrency requires restart", edit: func(c *config.Config) { c.MaxConcurrentToolCalls = 2 }},
		{name: "credential path requires restart", edit: func(c *config.Config) {
			c.CredentialsFile = filepath.Join(dir, "other-credentials.json")
			replaceGatewayMainFile(t, c.CredentialsFile, credentials)
		}},
		{name: "endpoint requires new version", edit: func(c *config.Config) { c.Tools[0].Endpoint = baseURL + "/changed-backend" }},
		{name: "method requires new version", edit: func(c *config.Config) { c.Tools[0].Method = "POST" }},
		{name: "schema requires new version", edit: func(c *config.Config) {
			c.Tools[0].InputSchema = json.RawMessage(`{"type":"object","additionalProperties":false}`)
		}},
		{name: "backend auth requires new version", edit: func(c *config.Config) { c.Tools[0].BackendTokenRequired = false },
			credentialData: []byte(fmt.Sprintf(`{"clients":{"demo":[{"token":%q}]},"backends":{},"metrics":[]}`, token))},
	}
	for i, tc := range rejections {
		candidate := gatewayMainTestConfig(addr, secretPath)
		if tc.edit != nil {
			tc.edit(&candidate)
		}
		data := tc.data
		if data == nil {
			data = marshalGatewayMainConfig(t, candidate)
		}
		replaceGatewayMainFile(t, configPath, data)
		replaceGatewayMainFile(t, secretPath, credentials)
		if tc.missingCredentials {
			if err := os.Remove(secretPath); err != nil {
				t.Fatal(err)
			}
		} else if tc.credentialData != nil {
			replaceGatewayMainFile(t, secretPath, tc.credentialData)
		}
		process.signal(t, syscall.SIGUSR1)
		process.waitForLog(t, rejectMessage, i+1)
		assertToolsList("rejected "+tc.name, disabledRevision, false)
		assertDisabledCall(disabledRevision)
	}

	replaceGatewayMainFile(t, secretPath, credentials)
	replaceGatewayMainFile(t, configPath, originalConfig)
	assertToolsList("rollback before SIGUSR1", disabledRevision, false)
	process.signal(t, syscall.SIGUSR1)
	process.waitForLog(t, reloadMessage, 2)
	assertToolsList("rollback after SIGUSR1", originalRevision, true)
	process.shutdown(t)
	assertGatewayLogRevisions(t, process.logs, reloadMessage, disabledRevision, originalRevision)
	wantRejectedRevisions := make([]string, len(rejections))
	for i := range wantRejectedRevisions {
		wantRejectedRevisions[i] = disabledRevision
	}
	assertGatewayLogRevisions(t, process.logs, rejectMessage, wantRejectedRevisions...)
	assertGatewayLogRevisions(t, process.logs, "credentials reloaded")
	assertGatewayLogsSafe(t, process.logs, token, backendToken, maliciousField, maliciousValue)
}

func TestMainCredentialReloadSignals(t *testing.T) {
	const (
		oldToken       = "old-test-token-0123456789-abcdefghijklmnopqrstuvwxyz"
		newToken       = "new-test-token-0123456789-abcdefghijklmnopqrstuvwxyz"
		maliciousField = "DO_NOT_LOG_ATTACKER_CONTROLLED_CREDENTIAL_FIELD"
		maliciousValue = "DO_NOT_LOG_ATTACKER_CONTROLLED_CREDENTIAL_VALUE"
		reloadMessage  = "credentials reloaded"
		rejectMessage  = "credential reload rejected; previous credentials remain active"
	)

	dir := t.TempDir()
	secretPath := filepath.Join(dir, "credentials.json")
	configPath := filepath.Join(dir, "gateway.json")
	// Every replacement is a new owner-only regular file in the same directory.
	replaceSecret := func(data string) {
		t.Helper()
		stagedPath := filepath.Join(dir, "credentials.next")
		if err := os.WriteFile(stagedPath, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(stagedPath, secretPath); err != nil {
			t.Fatal(err)
		}
	}
	secretJSON := func(token string) string {
		return fmt.Sprintf(`{"clients":{"demo":[{"token":%q,"revoked":false}]},"backends":{},"metrics":[]}`, token)
	}
	replaceSecret(secretJSON(oldToken))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	addr := listener.Addr().String()
	baseURL := "http://" + addr
	cfg, err := json.Marshal(map[string]any{
		"listen_addr":      addr,
		"credentials_file": secretPath,
		"clients": []any{
			map[string]any{"id": "demo", "allowed_tools": []string{"demo_tool"}},
		},
		"tools": []any{
			map[string]any{
				"name": "demo_tool", "description": "Signal reload test tool", "method": "GET",
				// Discovery never calls the backend; keep even this unused URL local.
				"endpoint":     baseURL + "/unused-backend",
				"input_schema": map[string]any{"type": "object"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, cfg, 0600); err != nil {
		t.Fatal(err)
	}

	// main owns its listener, so release the reserved ephemeral port just before start.
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	process := startGatewayMainProcess(t, configPath, false)
	cmd, logs := process.cmd, process.logs
	waitForLog := func(message string, wantCount int) {
		t.Helper()
		process.waitForLog(t, message, wantCount)
	}
	transport := &http.Transport{}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	process.waitForReady(t, client, baseURL)

	assertToolsList := func(stage, token string, wantStatus int) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(
			`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: tools/list request failed: %v", stage, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			t.Fatalf("%s: read tools/list response: %v", stage, err)
		}
		if resp.StatusCode != wantStatus {
			t.Fatalf("%s: HTTP status = %d, want %d", stage, resp.StatusCode, wantStatus)
		}
		if wantStatus != http.StatusOK {
			return
		}
		var rpc struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      int             `json:"id"`
			Error   json.RawMessage `json:"error"`
			Result  struct {
				Tools []struct {
					Name string `json:"name"`
				} `json:"tools"`
			} `json:"result"`
		}
		if err := json.Unmarshal(body, &rpc); err != nil {
			t.Fatalf("%s: invalid JSON-RPC response: %v", stage, err)
		}
		if rpc.JSONRPC != "2.0" || rpc.ID != 1 || len(rpc.Error) != 0 || len(rpc.Result.Tools) != 1 || rpc.Result.Tools[0].Name != "demo_tool" {
			t.Fatalf("%s: expected successful discovery of demo_tool", stage)
		}
	}

	assertToolsList("startup old token", oldToken, http.StatusOK)
	assertToolsList("startup new token", newToken, http.StatusUnauthorized)
	replaceSecret(secretJSON(newToken))
	assertToolsList("before SIGHUP old token", oldToken, http.StatusOK)
	assertToolsList("before SIGHUP new token", newToken, http.StatusUnauthorized)
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitForLog(reloadMessage, 1)
	assertToolsList("after reload new token", newToken, http.StatusOK)
	assertToolsList("after reload old token", oldToken, http.StatusUnauthorized)

	// Decoder errors must not leak attacker-controlled field names.
	for i, invalid := range []string{
		fmt.Sprintf(`{"clients":{"demo":[{"token":%q}]},%q:%q`, oldToken, maliciousField, maliciousValue),
		fmt.Sprintf(`{"clients":{"demo":[{"token":%q}]},"backends":{},"metrics":[],%q:%q}`, oldToken, maliciousField, maliciousValue),
	} {
		replaceSecret(invalid)
		if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		waitForLog(rejectMessage, i+1)
		assertToolsList(fmt.Sprintf("rejected reload %d new token", i+1), newToken, http.StatusOK)
		assertToolsList(fmt.Sprintf("rejected reload %d old token", i+1), oldToken, http.StatusUnauthorized)
	}

	process.shutdown(t)
	if got := logs.messageCount(reloadMessage); got != 1 {
		t.Errorf("successful reload count = %d, want 1", got)
	}
	if got := logs.messageCount(rejectMessage); got != 2 {
		t.Errorf("rejected reload count = %d, want 2", got)
	}
	for label, secret := range map[string]string{
		"old token": oldToken, "new token": newToken,
		"malicious field": maliciousField, "malicious value": maliciousValue,
	} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("gateway logs leaked %s", label)
		}
	}
}
