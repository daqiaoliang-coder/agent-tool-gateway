package main

import (
	"bytes"
	"context"
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
)

const gatewayHelperConfigEnv = "GATEWAY_MAIN_TEST_HELPER_CONFIG"

// Reuse the current test executable while exercising the real main signal loop.
func TestGatewayMainHelperProcess(t *testing.T) {
	configPath := os.Getenv(gatewayHelperConfigEnv)
	if configPath == "" {
		return
	}
	os.Args = []string{os.Args[0], "-config", configPath}
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

func (l *gatewayProcessLogs) messageCount(message string) int {
	count := 0
	for _, line := range strings.Split(l.String(), "\n") {
		var entry struct {
			Message string `json:"msg"`
		}
		if json.Unmarshal([]byte(line), &entry) == nil && entry.Message == message {
			count++
		}
	}
	return count
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

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	logs := &gatewayProcessLogs{changed: make(chan struct{}, 1)}
	cmd := exec.Command(executable, "-test.run=^TestGatewayMainHelperProcess$")
	cmd.Env = append(os.Environ(), gatewayHelperConfigEnv+"="+configPath)
	cmd.Stdout, cmd.Stderr = logs, logs
	cmd.WaitDelay = 2 * time.Second
	// main owns its listener, so release the reserved ephemeral port just before start.
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done) // Publishes waitErr and ensures all captured output is drained.
	}()
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
		}
		// Only kill the helper we started, and only if the test did not stop it.
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("gateway helper did not exit during cleanup")
		}
	})

	waitForLog := func(message string, wantCount int) {
		t.Helper()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		for logs.messageCount(message) < wantCount {
			select {
			case <-logs.changed:
			case <-done:
				t.Fatalf("gateway exited while waiting for %q: %v", message, waitErr)
			case <-timer.C:
				t.Fatalf("timed out waiting for occurrence %d of %q", wantCount, message)
			}
		}
	}
	waitForLog("agent tool gateway listening", 1)

	transport := &http.Transport{}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	// The startup log precedes socket binding, so readiness needs a separate probe.
	func() {
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
			case <-done:
				t.Fatalf("gateway exited before becoming healthy: %v", waitErr)
			case <-ctx.Done():
				t.Fatalf("gateway health probe timed out: %v", ctx.Err())
			case <-ticker.C:
			}
		}
	}()

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

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		if waitErr != nil {
			t.Fatalf("SIGTERM should shut down normally: %v", waitErr)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("gateway did not shut down after SIGTERM")
	}
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
