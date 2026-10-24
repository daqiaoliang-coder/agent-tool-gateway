package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
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
	Description          string          `json:"description"`
	Method               string          `json:"method"`
	Endpoint             string          `json:"endpoint"`
	BackendTokenEnv      string          `json:"backend_token_env,omitempty"`
	BackendTokenRequired bool            `json:"backend_token_required,omitempty"`
	InputSchema          json.RawMessage `json:"input_schema"`
}

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if len(data) > maxConfigBytes {
		return Config{}, fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("config must contain a single JSON value")
		}
		return Config{}, fmt.Errorf("decode trailing config data: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
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
		t.Method = strings.ToUpper(strings.TrimSpace(t.Method))
		if t.Method != "GET" && t.Method != "POST" && t.Method != "PUT" && t.Method != "PATCH" && t.Method != "DELETE" {
			return fmt.Errorf("tool %q has unsupported HTTP method %q", t.Name, t.Method)
		}
		u, err := url.ParseRequestURI(t.Endpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return fmt.Errorf("tool %q endpoint must be an absolute http(s) URL without user info", t.Name)
		}
		if len(t.InputSchema) == 0 || !json.Valid(t.InputSchema) {
			return fmt.Errorf("tool %q input_schema must be valid JSON", t.Name)
		}
		var schema struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(t.InputSchema, &schema); err != nil || schema.Type != "object" {
			return fmt.Errorf("tool %q input_schema must have type object", t.Name)
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
