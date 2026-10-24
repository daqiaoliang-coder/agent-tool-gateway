package config

import (
	"encoding/json"
	"strings"
	"testing"
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
