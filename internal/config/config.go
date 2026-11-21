package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxConfigBytes = 1 << 20

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type Config struct {
	ListenAddr             string   `json:"listen_addr"`
	ServerName             string   `json:"server_name"`
	ServerVersion          string   `json:"server_version"`
	RequestTimeout         string   `json:"request_timeout"`
	MaxRequestBytes        int64    `json:"max_request_bytes"`
	MaxResponseBytes       int64    `json:"max_response_bytes"`
	MaxConcurrentToolCalls int      `json:"max_concurrent_tool_calls"`
	MetricsTokenEnv        string   `json:"metrics_token_env,omitempty"`
	CredentialsFile        string   `json:"credentials_file,omitempty"`
	Clients                []Client `json:"clients"`
	Tools                  []Tool   `json:"tools"`
	requestTimeout         time.Duration
}

type Client struct {
	ID           string   `json:"id"`
	TokenEnv     string   `json:"token_env"`
	AllowedTools []string `json:"allowed_tools"`
}

type Tool struct {
	Name                 string          `json:"name"`
	Version              string          `json:"version,omitempty"`
	State                string          `json:"state,omitempty"`
	Description          string          `json:"description"`
	Method               string          `json:"method"`
	Endpoint             string          `json:"endpoint"`
	BackendTokenEnv      string          `json:"backend_token_env,omitempty"`
	BackendTokenRequired bool            `json:"backend_token_required,omitempty"`
	InputSchema          json.RawMessage `json:"input_schema"`
}

func Load(path string) (Config, error) {
	// Nonblocking open prevents a FIFO from hanging before we can check its mode.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("stat config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Config{}, errors.New("config must be a regular file")
	}
	if info.Size() > maxConfigBytes {
		return Config{}, fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if len(data) > maxConfigBytes {
		return Config{}, fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}
	// Decoder errors can include secret values or attacker-controlled keys.
	if !json.Valid(data) {
		return Config{}, errors.New("decode config: must contain a single valid JSON value")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := checkJSON(dec, "config"); err != nil {
		return Config{}, fmt.Errorf("decode config at byte %d: %w", dec.InputOffset(), err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, errors.New("decode config: invalid field type")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Only input_schema has an open, case-sensitive vocabulary.
var configFields = map[string]map[string]string{
	"config": {
		"listen_addr": "value", "server_name": "value", "server_version": "value",
		"request_timeout": "value", "max_request_bytes": "value", "max_response_bytes": "value",
		"max_concurrent_tool_calls": "value", "metrics_token_env": "value", "credentials_file": "value",
		"clients": "clients", "tools": "tools",
	},
	"client": {"id": "value", "token_env": "value", "allowed_tools": "allowlist"},
	"tool": {
		"name": "value", "version": "value", "state": "value", "description": "value",
		"method": "value", "endpoint": "value", "backend_token_env": "value",
		"backend_token_required": "value", "input_schema": "input_schema",
	},
}

// Struct decoding alone silently accepts duplicate keys, case aliases and nulls.
func checkJSON(dec *json.Decoder, scope string) error {
	token, err := dec.Token()
	if err != nil {
		return errors.New("invalid JSON")
	}
	if token == nil && scope != "schema" {
		return errors.New("null is not allowed outside input_schema")
	}
	fields := configFields[scope]
	if fields != nil && token != json.Delim('{') {
		return fmt.Errorf("%s must be an object", scope)
	}
	elementScope := "value"
	switch scope {
	case "clients":
		elementScope = "client"
	case "tools":
		elementScope = "tool"
	case "schema", "input_schema":
		elementScope = "schema"
	}
	if (scope == "clients" || scope == "tools" || scope == "allowlist") && token != json.Delim('[') {
		return fmt.Errorf("%s must be an array", scope)
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return errors.New("invalid JSON")
			}
			key := keyToken.(string)
			if seen[key] {
				return errors.New("duplicate JSON key")
			}
			seen[key] = true
			childScope := elementScope
			if fields != nil {
				var ok bool
				childScope, ok = fields[key]
				if !ok {
					return fmt.Errorf("unknown or case-variant %s field", scope)
				}
			}
			if err := checkJSON(dec, childScope); err != nil {
				return err
			}
		}
	case json.Delim('['):
		for dec.More() {
			if err := checkJSON(dec, elementScope); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	if _, err := dec.Token(); err != nil {
		return errors.New("invalid JSON")
	}
	return nil
}

func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	if c.ServerName == "" {
		c.ServerName = "agent-tool-gateway"
	}
	if c.ServerVersion == "" {
		c.ServerVersion = "0.1.0"
	}
	if c.RequestTimeout == "" {
		c.RequestTimeout = "10s"
	}
	d, err := time.ParseDuration(c.RequestTimeout)
	if err != nil || d <= 0 {
		return fmt.Errorf("request_timeout must be a positive duration")
	}
	c.requestTimeout = d
	if c.MaxRequestBytes <= 0 {
		c.MaxRequestBytes = 1 << 20
	}
	if c.MaxResponseBytes <= 0 {
		c.MaxResponseBytes = 1 << 20
	}
	if c.MaxConcurrentToolCalls <= 0 {
		c.MaxConcurrentToolCalls = 64
	}
	fileCredentials := c.CredentialsFile != ""
	if fileCredentials && c.MetricsTokenEnv != "" {
		return errors.New("metrics_token_env must be empty when credentials_file is set")
	}
	if err := validateEnvName(c.MetricsTokenEnv); err != nil {
		return fmt.Errorf("metrics_token_env: %w", err)
	}
	if len(c.Clients) == 0 {
		return errors.New("at least one client must be configured")
	}
	if len(c.Tools) == 0 {
		return errors.New("at least one tool must be configured")
	}

	toolNames := make(map[string]struct{}, len(c.Tools))
	for i := range c.Tools {
		t := &c.Tools[i]
		if !validToolName(t.Name) {
			return fmt.Errorf("tools[%d].name must use only letters, digits, '.', '_' or '-'", i)
		}
		if _, exists := toolNames[t.Name]; exists {
			return fmt.Errorf("duplicate tool name %q", t.Name)
		}
		toolNames[t.Name] = struct{}{}
		if t.Version == "" {
			t.Version = "1"
		}
		if !validToolName(t.Version) {
			return fmt.Errorf("tool %q version must use only letters, digits, '.', '_' or '-' and be at most 128 characters", t.Name)
		}
		if t.State == "" {
			t.State = "active"
		}
		switch t.State {
		case "active", "deprecated", "disabled":
		default:
			return fmt.Errorf("tool %q state must be active, deprecated or disabled", t.Name)
		}
		t.Method = strings.ToUpper(strings.TrimSpace(t.Method))
		if t.Method != "GET" && t.Method != "POST" && t.Method != "PUT" && t.Method != "PATCH" && t.Method != "DELETE" {
			return fmt.Errorf("tool %q has unsupported HTTP method %q", t.Name, t.Method)
		}
		u, err := url.ParseRequestURI(t.Endpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return fmt.Errorf("tool %q endpoint must be an absolute http(s) URL without user info", t.Name)
		}
		if err := validateInputSchema(t.InputSchema); err != nil {
			return fmt.Errorf("tool %q %w", t.Name, err)
		}
		if fileCredentials && t.BackendTokenEnv != "" {
			return fmt.Errorf("tool %q backend_token_env must be empty when credentials_file is set", t.Name)
		}
		if !fileCredentials && t.BackendTokenRequired && t.BackendTokenEnv == "" {
			return fmt.Errorf("tool %q backend_token_env is required when backend_token_required is true", t.Name)
		}
		if err := validateEnvName(t.BackendTokenEnv); err != nil {
			return fmt.Errorf("tool %q backend_token_env: %w", t.Name, err)
		}
	}

	clientIDs := make(map[string]struct{}, len(c.Clients))
	for i, client := range c.Clients {
		if strings.TrimSpace(client.ID) == "" {
			return fmt.Errorf("clients[%d].id is required", i)
		}
		if _, exists := clientIDs[client.ID]; exists {
			return fmt.Errorf("duplicate client id %q", client.ID)
		}
		clientIDs[client.ID] = struct{}{}
		if fileCredentials && client.TokenEnv != "" {
			return fmt.Errorf("client %q token_env must be empty when credentials_file is set", client.ID)
		}
		if err := validateEnvName(client.TokenEnv); err != nil {
			return fmt.Errorf("client %q token_env: %w", client.ID, err)
		}
		if !fileCredentials && client.TokenEnv == "" {
			return fmt.Errorf("client %q token_env is required", client.ID)
		}
		if len(client.AllowedTools) == 0 {
			return fmt.Errorf("client %q must have an explicit allowed_tools list", client.ID)
		}
		seen := make(map[string]struct{}, len(client.AllowedTools))
		for _, name := range client.AllowedTools {
			if _, ok := toolNames[name]; !ok {
				return fmt.Errorf("client %q allows unknown tool %q", client.ID, name)
			}
			if _, ok := seen[name]; ok {
				return fmt.Errorf("client %q repeats allowed tool %q", client.ID, name)
			}
			seen[name] = struct{}{}
		}
	}
	return nil
}

func (c Config) Timeout() time.Duration { return c.requestTimeout }

// Revision hashes a validated config without rounding schema numbers through float64.
func (c Config) Revision() string {
	data, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return ""
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(canonical))
}

// Clone returns a config with independently owned slices and raw schemas.
func (c Config) Clone() Config {
	c.Clients = slices.Clone(c.Clients)
	for i := range c.Clients {
		c.Clients[i].AllowedTools = slices.Clone(c.Clients[i].AllowedTools)
	}
	c.Tools = slices.Clone(c.Tools)
	for i := range c.Tools {
		c.Tools[i].InputSchema = bytes.Clone(c.Tools[i].InputSchema)
	}
	return c
}

func validateInputSchema(data json.RawMessage) (err error) {
	// SDK registration panics must reject releases without exposing schema contents.
	defer func() {
		if recover() != nil {
			err = errors.New("input_schema could not be compiled")
		}
	}()
	if len(data) == 0 || !json.Valid(data) {
		return errors.New("input_schema must be valid JSON")
	}
	var object map[string]json.RawMessage
	var schemaType string
	if json.Unmarshal(data, &object) != nil || json.Unmarshal(object["type"], &schemaType) != nil || schemaType != "object" {
		return errors.New("input_schema must have type object")
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(data, &schema); err != nil {
		return errors.New("input_schema is not a valid JSON Schema")
	}
	if _, err := schema.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: true}); err != nil {
		return errors.New("input_schema cannot be resolved or has invalid defaults")
	}
	// SDK-specific schema annotations have additional registration-time checks.
	server := mcp.NewServer(&mcp.Implementation{Name: "config-validation", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "validation", InputSchema: data},
		func(context.Context, *mcp.CallToolRequest, map[string]any) (*mcp.CallToolResult, any, error) {
			return nil, nil, nil
		})
	return nil
}

func validateEnvName(name string) error {
	if name == "" {
		return nil
	}
	if !envNamePattern.MatchString(name) {
		return errors.New("must be a valid environment variable name")
	}
	return nil
}

func validToolName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
