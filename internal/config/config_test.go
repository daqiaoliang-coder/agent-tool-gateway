package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func validConfig() Config {
	return Config{
		Clients: []Client{{ID: "agent", TokenEnv: "CLIENT_TOKEN", AllowedTools: []string{"lookup"}}},
		Tools: []Tool{{
			Name:        "lookup",
			Method:      "POST",
			Endpoint:    "https://example.com/lookup",
			InputSchema: json.RawMessage(`{"type":"object"}`),
		}},
	}
}

func loadJSON(t *testing.T, data string) (Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func configJSON(t *testing.T) string {
	t.Helper()
	data, err := json.Marshal(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestLoadFixedFields(t *testing.T) {
	cfg := validConfig()
	for _, object := range []struct {
		name  string
		value any
		wrap  func(string) string
	}{
		{"config", cfg, func(s string) string { return s }},
		{"client", cfg.Clients[0], func(s string) string {
			return `{"clients":[` + s + `],"tools":[{"name":"lookup","method":"POST","endpoint":"https://example.com","input_schema":{"type":"object"}}]}`
		}},
		{"tool", cfg.Tools[0], func(s string) string {
			return `{"clients":[{"id":"agent","token_env":"CLIENT_TOKEN","allowed_tools":["lookup"]}],"tools":[` + s + `]}`
		}},
	} {
		t.Run(object.name, func(t *testing.T) {
			base, err := json.Marshal(object.value)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(base, &fields); err != nil {
				t.Fatal(err)
			}
			// Reflect the public JSON fields so optional fields cannot accidentally
			// escape exact-key and null checks as the structs evolve.
			typ := reflect.TypeOf(object.value)
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				key := strings.Split(field.Tag.Get("json"), ",")[0]
				if key == "" {
					continue
				}
				value := fields[key]
				if value == nil {
					value, err = json.Marshal(reflect.Zero(field.Type).Interface())
					if err != nil {
						t.Fatal(err)
					}
				}
				for _, test := range []struct {
					name, prefix, wantErr string
				}{
					{"null", fmt.Sprintf(`%q:null,`, key), "null"},
					{"case alias", fmt.Sprintf(`%q:%s,`, strings.ToUpper(key), value), "case-variant"},
					{"duplicate", fmt.Sprintf(`%q:%s,%q:%s,`, key, value, key, value), "duplicate JSON key"},
				} {
					t.Run(key+"/"+test.name, func(t *testing.T) {
						_, err := loadJSON(t, object.wrap("{"+test.prefix+string(base[1:])))
						if err == nil || !strings.Contains(err.Error(), test.wantErr) {
							t.Fatalf("Load() error = %v, want %q", err, test.wantErr)
						}
					})
				}
				// A case alias must fail even when no correctly cased key exists.
				t.Run(key+"/case only", func(t *testing.T) {
					_, err := loadJSON(t, object.wrap(fmt.Sprintf(`{%q:%s}`, strings.ToUpper(key), value)))
					if err == nil || !strings.Contains(err.Error(), "case-variant") {
						t.Fatalf("Load() error = %v, want case-variant field error", err)
					}
				})
			}
			t.Run("unknown", func(t *testing.T) {
				_, err := loadJSON(t, object.wrap(`{"private-field":"private-value",`+string(base[1:])))
				if err == nil || !strings.Contains(err.Error(), "unknown") || strings.Contains(err.Error(), "private-") {
					t.Fatalf("Load() error = %v, want sanitized unknown field error", err)
				}
			})
		})
	}
}

func TestLoadInvalidJSONAndShapes(t *testing.T) {
	base := configJSON(t)
	for _, test := range []struct{ name, data string }{
		{"empty", ""},
		{"truncated", base[:len(base)-1]},
		{"root null", "null"},
		{"root array", "[]"},
		{"root string", `"private-value"`},
		{"root bool", "true"},
		{"root number", "42"},
		{"trailing object", base + `{}`},
		{"trailing null", base + `null`},
		{"trailing garbage", base + `private-value`},
		{"clients object", `{"clients":{}}`},
		{"client null", `{"clients":[null]}`},
		{"client string", `{"clients":["private-value"]}`},
		{"client array", `{"clients":[[]]}`},
		{"tools object", `{"tools":{}}`},
		{"tool null", `{"tools":[null]}`},
		{"tool number", `{"tools":[42]}`},
		{"tool array", `{"tools":[[]]}`},
		{"allowlist object", `{"clients":[{"allowed_tools":{}}]}`},
		{"allowlist null item", `{"clients":[{"allowed_tools":[null]}]}`},
		{"allowlist object item", `{"clients":[{"allowed_tools":[{"private-field":1}]}]}`},
		{"string wrong type", `{"server_name":{"private-field":1}}`},
		{"number wrong type", `{"max_request_bytes":"private-value"}`},
		{"number overflow", `{"max_request_bytes":123456789012345678901234567890}`},
		{"boolean wrong type", `{"tools":[{"backend_token_required":"private-value"}]}`},
		{"escaped duplicate", `{"server_name":"one","server\u005fname":"private-value"}`},
		{"too deeply nested", `{"tools":` + strings.Repeat("[", 10001) + strings.Repeat("]", 10001) + `}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadJSON(t, test.data)
			if err == nil {
				t.Fatal("Load() succeeded")
			}
			if strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), "12345678901234567890") {
				t.Fatalf("Load() exposed JSON content: %v", err)
			}
		})
	}
}

func TestLoadSchemaKeys(t *testing.T) {
	for _, schema := range []string{
		`{"type":"object","type":"object"}`,
		`{"type":"object","properties":{"private-key":{},"private-key":{}}}`,
		`{"type":"object","properties":{"a":{"type":"string","type":"string"}}}`,
		`{"type":"object","x-data":[{"private-key":null,"private-key":null}]}`,
		`{"type":"object","x-data":{"name":1,"\u006eame":2}}`,
	} {
		t.Run(schema, func(t *testing.T) {
			data := strings.Replace(configJSON(t), `{"type":"object"}`, schema, 1)
			_, err := loadJSON(t, data)
			if err == nil || !strings.Contains(err.Error(), "duplicate JSON key") || strings.Contains(err.Error(), "private-key") {
				t.Fatalf("Load() error = %v, want sanitized duplicate key error", err)
			}
		})
	}
	// Dynamic schema keys are not config fields: preserve case, arbitrary names,
	// annotations, null data and nested boolean schemas.
	schema := `{"type":"object","properties":{"Name":{"type":["string","null"],"default":null,"enum":[null,"ok"],"const":null},"name":true,"state":false},"x-data":{"clients":null,"Version":[null,{"id":null}],"version":null}}`
	data := strings.Replace(configJSON(t), `{"type":"object"}`, schema, 1)
	cfg, err := loadJSON(t, data)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if string(cfg.Tools[0].InputSchema) != schema {
		t.Fatal("Load() changed the raw schema")
	}
}

func TestLoadFileLimits(t *testing.T) {
	base := configJSON(t)
	if _, err := loadJSON(t, base+strings.Repeat(" ", maxConfigBytes-len(base))); err != nil {
		t.Fatalf("Load() at limit: %v", err)
	}
	if _, err := loadJSON(t, base+strings.Repeat(" ", maxConfigBytes-len(base)+1)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Load() over limit: %v", err)
	}
	if _, err := Load(t.TempDir()); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Load(directory) error = %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("Load(missing) succeeded")
	}
	t.Run("FIFO without writer", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.fifo")
		if err := syscall.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := Load(path)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "regular file") {
				t.Fatalf("Load(FIFO) error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Load(FIFO) blocked")
		}
	})
}

func TestValidateToolRelease(t *testing.T) {
	for _, test := range []struct {
		name, version, state, wantVersion, wantState, wantErr string
	}{
		{"defaults", "", "", "1", "active", ""},
		{"active", "release_A-1.2", "active", "release_A-1.2", "active", ""},
		{"deprecated", "2", "deprecated", "2", "deprecated", ""},
		{"disabled and allowlisted", "3", "disabled", "3", "disabled", ""},
		{"version limit", strings.Repeat("a", 128), "", strings.Repeat("a", 128), "active", ""},
		{"version too long", strings.Repeat("a", 129), "", "", "", "version"},
		{"version slash", "v/2", "", "", "", "version"},
		{"version semver plus", "1+build", "", "", "", "version"},
		{"version spaces", " 1 ", "", "", "", "version"},
		{"version unicode", "版本", "", "", "", "version"},
		{"version control", "v\n1", "", "", "", "version"},
		{"unknown state", "", "archived", "", "", "state"},
		{"state case", "", "Active", "", "", "state"},
		{"state whitespace", "", " active ", "", "", "state"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Tools[0].Version, cfg.Tools[0].State = test.version, test.state
			err := cfg.Validate()
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("Validate() error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Tools[0].Version != test.wantVersion || cfg.Tools[0].State != test.wantState {
				t.Fatalf("unexpected release metadata: %+v", cfg.Tools[0])
			}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := loadJSON(t, string(data))
			if err != nil || !reflect.DeepEqual(loaded, cfg) {
				t.Fatalf("release metadata did not round trip: %v", err)
			}
		})
	}
}

func TestValidateSchemas(t *testing.T) {
	for _, test := range []struct{ name, schema, wantErr string }{
		{"missing", "", "must be valid JSON"},
		{"invalid JSON", "{", "must be valid JSON"},
		{"null", "null", "must have type object"},
		{"array", "[]", "must have type object"},
		{"boolean", "true", "must have type object"},
		{"missing type", "{}", "must have type object"},
		{"wrong type", `{"type":"string"}`, "must have type object"},
		{"case sensitive type", `{"Type":"object"}`, "must have type object"},
		{"invalid keyword type", `{"type":"object","properties":42}`, "not a valid JSON Schema"},
		{"bad pattern", `{"type":"object","properties":{"x":{"type":"string","pattern":"[private-value"}}}`, "cannot be resolved"},
		{"bad pattern property", `{"type":"object","patternProperties":{"[private-value":{}}}`, "cannot be resolved"},
		{"missing ref", `{"type":"object","properties":{"x":{"$ref":"#/$defs/private-value"}}}`, "cannot be resolved"},
		{"malformed ref", `{"type":"object","$ref":"%private-value"}`, "cannot be resolved"},
		{"remote ref", `{"type":"object","$ref":"https://example.invalid/private-value"}`, "cannot be resolved"},
		{"invalid root default", `{"type":"object","default":"private-value"}`, "invalid defaults"},
		{"invalid nested default", `{"type":"object","properties":{"x":{"type":"integer","default":"private-value"}}}`, "invalid defaults"},
		{"invalid unused definition", `{"type":"object","$defs":{"unused":{"type":"string","pattern":"[private-value"}}}`, "cannot be resolved"},
		{"invalid unused default", `{"type":"object","$defs":{"unused":{"type":"integer","default":"private-value"}}}`, "invalid defaults"},
		{"null subschema", `{"type":"object","properties":{"x":null}}`, "cannot be resolved"},
		{"invalid SDK header annotation", `{"type":"object","properties":{"x":{"type":"array","x-mcp-header":"X"}}}`, "could not be compiled"},
		{"invalid subschema type shape", `{"type":"object","properties":{"x":{"type":false}}}`, "not a valid JSON Schema"},
		{"local ref and default", `{"type":"object","$defs":{"text":{"type":"string","default":"ok"}},"properties":{"x":{"$ref":"#/$defs/text"}}}`, ""},
		{"nested defaults", `{"type":"object","properties":{"x":{"type":"integer","default":42}},"default":{"x":1}}`, ""},
	} {
		for _, state := range []string{"active", "deprecated", "disabled"} {
			for _, unassigned := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/unassigned=%t", test.name, state, unassigned), func(t *testing.T) {
					cfg := validConfig()
					index := 0
					if unassigned {
						cfg.Tools = append(cfg.Tools, cfg.Tools[0])
						index = 1
						cfg.Tools[index].Name = "unassigned"
					}
					cfg.Tools[index].State = state
					cfg.Tools[index].InputSchema = json.RawMessage(test.schema)
					err := cfg.Validate()
					if test.wantErr == "" {
						if err != nil {
							t.Fatal(err)
						}
						return
					}
					if err == nil || !strings.Contains(err.Error(), test.wantErr) || strings.Contains(err.Error(), "private-value") {
						t.Fatalf("Validate() error = %v, want sanitized %q", err, test.wantErr)
					}
				})
			}
		}
	}
}

func TestDisabledToolStillValidated(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*Tool)
	}{
		{"name", func(tool *Tool) { tool.Name = "bad/name" }},
		{"version", func(tool *Tool) { tool.Version = "bad/version" }},
		{"method", func(tool *Tool) { tool.Method = "INVALID" }},
		{"endpoint", func(tool *Tool) { tool.Endpoint = "/relative" }},
		{"backend env", func(tool *Tool) { tool.BackendTokenEnv = "BAD-NAME" }},
		{"required backend", func(tool *Tool) { tool.BackendTokenRequired = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Tools[0].State = "disabled"
			test.edit(&cfg.Tools[0])
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid disabled tool was accepted")
			}
		})
	}
}

func TestRevisionCanonical(t *testing.T) {
	first := strings.Replace(configJSON(t), `{"type":"object"}`, `{"type":"object","x-data":{"z":9007199254740993,"a":[null,{"b":2,"a":1}]}}`, 1)
	second := `{
		"tools": [{"state":"active", "version":"1", "endpoint":"https://example.com/lookup",
			"input_schema": {"x-data": {"a": [null, {"a":1,"b":2}], "z":9007199254740993}, "type":"object"},
			"method":" post ", "name":"lookup"}],
		"clients": [{"allowed_tools":["lookup"], "token_env":"CLIENT_TOKEN", "id":"agent"}]
	}`
	a, err := loadJSON(t, first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadJSON(t, second)
	if err != nil {
		t.Fatal(err)
	}
	before := a.Clone()
	revision := a.Revision()
	if len(revision) != 64 || revision != b.Revision() || revision != a.Revision() {
		t.Fatalf("unstable revision: %q vs %q", revision, b.Revision())
	}
	if !reflect.DeepEqual(a, before) {
		t.Fatal("Revision() mutated the config")
	}
	// Independent canonical document verifies the digest includes normalized
	// config fields and preserves integers above float64's exact range.
	canonical := `{"clients":[{"allowed_tools":["lookup"],"id":"agent","token_env":"CLIENT_TOKEN"}],"listen_addr":":8080","max_concurrent_tool_calls":64,"max_request_bytes":1048576,"max_response_bytes":1048576,"request_timeout":"10s","server_name":"agent-tool-gateway","server_version":"0.1.0","tools":[{"description":"","endpoint":"https://example.com/lookup","input_schema":{"type":"object","x-data":{"a":[null,{"a":1,"b":2}],"z":9007199254740993}},"method":"POST","name":"lookup","state":"active","version":"1"}]}`
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(canonical)))
	if revision != want {
		t.Fatalf("Revision() = %s, want SHA-256 %s", revision, want)
	}
	t.Setenv("CLIENT_TOKEN", "first-private-secret")
	if a.Revision() != revision {
		t.Fatal("Revision() depends on environment secret values")
	}
	t.Setenv("CLIENT_TOKEN", "second-private-secret")
	if a.Revision() != revision {
		t.Fatal("Revision() depends on environment secret values")
	}
	b.Tools[0].InputSchema = json.RawMessage(strings.Replace(string(b.Tools[0].InputSchema), "9007199254740993", "9007199254740992", 1))
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if revision == b.Revision() {
		t.Fatal("Revision() rounded distinct large integers together")
	}
	invalid := validConfig()
	invalid.Tools[0].InputSchema = json.RawMessage("{")
	if invalid.Revision() != "" {
		t.Fatal("invalid JSON produced a revision")
	}
}

func TestRevisionChanges(t *testing.T) {
	base := validConfig()
	base.Tools = append(base.Tools, Tool{Name: "other", Method: "GET", Endpoint: "https://example.com/other", InputSchema: json.RawMessage(`{"type":"object"}`)})
	base.Clients = append(base.Clients, Client{ID: "other-agent", TokenEnv: "OTHER_TOKEN", AllowedTools: []string{"other"}})
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*Config)
	}{
		{"listen addr", func(c *Config) { c.ListenAddr = ":9090" }},
		{"server name", func(c *Config) { c.ServerName = "other" }},
		{"server version", func(c *Config) { c.ServerVersion = "2" }},
		{"timeout", func(c *Config) { c.RequestTimeout = "1s" }},
		{"request size", func(c *Config) { c.MaxRequestBytes++ }},
		{"response size", func(c *Config) { c.MaxResponseBytes++ }},
		{"concurrency", func(c *Config) { c.MaxConcurrentToolCalls++ }},
		{"metrics reference", func(c *Config) { c.MetricsTokenEnv = "METRICS_TOKEN" }},
		{"client id", func(c *Config) { c.Clients[0].ID = "renamed-agent" }},
		{"client token reference", func(c *Config) { c.Clients[0].TokenEnv = "CHANGED_TOKEN" }},
		{"allowlist", func(c *Config) { c.Clients[0].AllowedTools = append(c.Clients[0].AllowedTools, "other") }},
		{"client order", func(c *Config) { c.Clients[0], c.Clients[1] = c.Clients[1], c.Clients[0] }},
		{"tool order", func(c *Config) { c.Tools[0], c.Tools[1] = c.Tools[1], c.Tools[0] }},
		{"tool name", func(c *Config) { c.Tools[0].Name = "renamed"; c.Clients[0].AllowedTools[0] = "renamed" }},
		{"tool version", func(c *Config) { c.Tools[0].Version = "2" }},
		{"tool state", func(c *Config) { c.Tools[0].State = "disabled" }},
		{"description", func(c *Config) { c.Tools[0].Description = "Changed description" }},
		{"method", func(c *Config) { c.Tools[0].Method = "GET" }},
		{"endpoint", func(c *Config) { c.Tools[0].Endpoint = "https://example.com/new" }},
		{"backend reference", func(c *Config) { c.Tools[0].BackendTokenEnv = "BACKEND_TOKEN" }},
		{"schema", func(c *Config) {
			c.Tools[0].InputSchema = json.RawMessage(`{"type":"object","additionalProperties":false}`)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := base.Clone()
			test.edit(&changed)
			if err := changed.Validate(); err != nil {
				t.Fatal(err)
			}
			if changed.Revision() == base.Revision() {
				t.Fatal("changed content produced the same revision")
			}
		})
	}
	fileConfig := validConfig()
	fileConfig.Clients[0].TokenEnv = ""
	fileConfig.CredentialsFile = "credentials.json"
	if err := fileConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	revision := fileConfig.Revision()
	fileConfig.CredentialsFile = "other-credentials.json"
	if revision == fileConfig.Revision() {
		t.Fatal("credential file reference did not affect revision")
	}
	revision = fileConfig.Revision()
	fileConfig.Tools[0].BackendTokenRequired = true
	if err := fileConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	if revision == fileConfig.Revision() {
		t.Fatal("backend token requirement did not affect revision")
	}
}

func TestCloneIsolation(t *testing.T) {
	for _, direction := range []string{"change original", "change clone"} {
		t.Run(direction, func(t *testing.T) {
			original := validConfig()
			if err := original.Validate(); err != nil {
				t.Fatal(err)
			}
			clone := original.Clone()
			if !reflect.DeepEqual(clone, original) || clone.Timeout() != 10*time.Second {
				t.Fatal("Clone() did not preserve values or cached timeout")
			}
			want, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			changed, unchanged := &original, &clone
			if direction == "change clone" {
				changed, unchanged = &clone, &original
			}
			changed.ListenAddr = ":9999"
			changed.Clients[0].ID = "changed"
			changed.Clients[0].AllowedTools[0] = "changed"
			changed.Tools[0].Name = "changed"
			changed.Tools[0].Version = "2"
			changed.Tools[0].State = "disabled"
			changed.Tools[0].InputSchema[2] = 'T'
			changed.Clients = append(changed.Clients, Client{ID: "extra"})
			changed.Tools = append(changed.Tools, Tool{Name: "extra"})
			changed.Clients[0].AllowedTools = append(changed.Clients[0].AllowedTools, "extra")
			got, err := json.Marshal(unchanged)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("Clone() shares mutable storage")
			}
		})
	}
	for _, cfg := range []Config{
		{},
		{Clients: []Client{}, Tools: []Tool{}},
		{Clients: []Client{{AllowedTools: []string{}}}, Tools: []Tool{{InputSchema: json.RawMessage{}}}},
	} {
		if !reflect.DeepEqual(cfg, cfg.Clone()) {
			t.Fatal("Clone() changed nil or empty slices")
		}
	}
}

func TestValidateCredentialModes(t *testing.T) {
	tests := []struct {
		name            string
		credentialsFile string
		clientEnv       string
		backendEnv      string
		metricsEnv      string
		backendRequired bool
		wantErr         string
	}{
		{
			name:       "legacy env configuration",
			clientEnv:  "CLIENT_TOKEN",
			backendEnv: "BACKEND_TOKEN",
			metricsEnv: "METRICS_TOKEN",
		},
		{
			name:      "env without optional tokens",
			clientEnv: "CLIENT_TOKEN",
		},
		{
			name:    "env requires client token env",
			wantErr: `client "agent" token_env is required`,
		},
		{
			name:            "env required backend without token env",
			clientEnv:       "CLIENT_TOKEN",
			backendRequired: true,
			wantErr:         "backend_token_env is required when backend_token_required is true",
		},
		{
			name:            "env required backend with token env",
			clientEnv:       "CLIENT_TOKEN",
			backendEnv:      "BACKEND_TOKEN",
			backendRequired: true,
		},
		{
			name:            "file without token env",
			credentialsFile: "credentials.json",
		},
		{
			name:            "file required backend without token env",
			credentialsFile: "credentials.json",
			backendRequired: true,
		},
		{
			name:            "file rejects client token env",
			credentialsFile: "credentials.json",
			clientEnv:       "CLIENT_TOKEN",
			wantErr:         `client "agent" token_env must be empty when credentials_file is set`,
		},
		{
			name:            "file rejects backend token env",
			credentialsFile: "credentials.json",
			backendEnv:      "BACKEND_TOKEN",
			wantErr:         "backend_token_env must be empty when credentials_file is set",
		},
		{
			name:            "file required backend rejects token env",
			credentialsFile: "credentials.json",
			backendEnv:      "BACKEND_TOKEN",
			backendRequired: true,
			wantErr:         "backend_token_env must be empty when credentials_file is set",
		},
		{
			name:            "file rejects metrics token env",
			credentialsFile: "credentials.json",
			metricsEnv:      "METRICS_TOKEN",
			wantErr:         "metrics_token_env must be empty when credentials_file is set",
		},
		{
			name:      "env rejects invalid client env name",
			clientEnv: "CLIENT-TOKEN",
			wantErr:   `client "agent" token_env: must be a valid environment variable name`,
		},
		{
			name:       "env rejects invalid backend env name",
			clientEnv:  "CLIENT_TOKEN",
			backendEnv: "BACKEND-TOKEN",
			wantErr:    "backend_token_env: must be a valid environment variable name",
		},
		{
			name:       "env rejects invalid metrics env name",
			clientEnv:  "CLIENT_TOKEN",
			metricsEnv: "METRICS-TOKEN",
			wantErr:    "metrics_token_env: must be a valid environment variable name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.CredentialsFile = tt.credentialsFile
			cfg.Clients[0].TokenEnv = tt.clientEnv
			cfg.Tools[0].BackendTokenEnv = tt.backendEnv
			cfg.Tools[0].BackendTokenRequired = tt.backendRequired
			cfg.MetricsTokenEnv = tt.metricsEnv
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAllowlist(t *testing.T) {
	tests := []struct {
		name         string
		allowedTools []string
		wantErr      string
	}{
		{name: "valid", allowedTools: []string{"lookup"}},
		{name: "missing", wantErr: "must have an explicit allowed_tools list"},
		{name: "empty", allowedTools: []string{}, wantErr: "must have an explicit allowed_tools list"},
		{name: "unknown", allowedTools: []string{"missing"}, wantErr: `allows unknown tool "missing"`},
		{name: "duplicate", allowedTools: []string{"lookup", "lookup"}, wantErr: `repeats allowed tool "lookup"`},
	}
	for _, mode := range []string{"env", "file"} {
		t.Run(mode, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					cfg := validConfig()
					if mode == "file" {
						cfg.CredentialsFile = "credentials.json"
						cfg.Clients[0].TokenEnv = ""
					}
					cfg.Clients[0].AllowedTools = tt.allowedTools
					err := cfg.Validate()
					if tt.wantErr == "" {
						if err != nil {
							t.Fatalf("Validate() error = %v", err)
						}
						return
					}
					if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
						t.Fatalf("Validate() error = %v, want containing %q", err, tt.wantErr)
					}
				})
			}
		})
	}
}
