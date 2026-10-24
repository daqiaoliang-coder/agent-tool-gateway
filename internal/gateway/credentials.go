package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/daqiaoliang-coder/agent-tool-gateway/internal/config"
)

const maxCredentialsBytes = 1 << 20

var bearerTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/\-]+=*$`)

type tokenCredential struct {
	Token     string    `json:"token"`
	NotBefore time.Time `json:"not_before,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Revoked   bool      `json:"revoked,omitempty"`
}

func (c tokenCredential) active(now time.Time) bool {
	return !c.Revoked && !now.Before(c.NotBefore) && (c.ExpiresAt.IsZero() || now.Before(c.ExpiresAt))
}

func (c *tokenCredential) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return errors.New("credential must be an object")
	}
	for key, value := range fields {
		switch key {
		case "token", "not_before", "expires_at", "revoked":
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return errors.New("credential fields must not be null")
			}
		default:
			return errors.New("unknown credential field")
		}
	}
	type plainCredential tokenCredential
	return json.Unmarshal(data, (*plainCredential)(c))
}

type credentialSnapshot struct {
	Clients  map[string][]tokenCredential `json:"clients"`
	Backends map[string]tokenCredential   `json:"backends"`
	Metrics  []tokenCredential            `json:"metrics"`
}

func (s *credentialSnapshot) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return errors.New("credentials document must be an object")
	}
	for key := range fields {
		if key != "clients" && key != "backends" && key != "metrics" {
			return errors.New("unknown credentials document field")
		}
	}
	type plainSnapshot credentialSnapshot
	return json.Unmarshal(data, (*plainSnapshot)(s))
}

func loadCredentials(cfg config.Config) (*credentialSnapshot, error) {
	if cfg.CredentialsFile != "" {
		return loadCredentialFile(cfg)
	}
	snapshot := &credentialSnapshot{
		Clients:  make(map[string][]tokenCredential, len(cfg.Clients)),
		Backends: make(map[string]tokenCredential),
	}
	for _, client := range cfg.Clients {
		snapshot.Clients[client.ID] = []tokenCredential{{Token: os.Getenv(client.TokenEnv)}}
	}
	for _, tool := range cfg.Tools {
		if tool.BackendTokenEnv != "" {
			snapshot.Backends[tool.Name] = tokenCredential{Token: os.Getenv(tool.BackendTokenEnv)}
		}
	}
	if cfg.MetricsTokenEnv != "" {
		snapshot.Metrics = []tokenCredential{{Token: os.Getenv(cfg.MetricsTokenEnv)}}
	}
	if err := snapshot.validate(cfg); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func loadCredentialFile(cfg config.Config) (*credentialSnapshot, error) {
	f, err := os.OpenFile(cfg.CredentialsFile, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open credentials file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errors.New("cannot stat credentials file")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("credentials file must be a regular file accessible only by its owner")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCredentialsBytes+1))
	if err != nil {
		return nil, errors.New("cannot read credentials file")
	}
	if len(data) > maxCredentialsBytes {
		return nil, errors.New("credentials file exceeds size limit")
	}
	if !json.Valid(data) || uniqueJSONKeys(json.NewDecoder(bytes.NewReader(data))) != nil {
		return nil, errors.New("invalid credentials JSON")
	}
	var snapshot *credentialSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil || snapshot == nil {
		// JSON errors may contain secret values or attacker-controlled field names.
		return nil, errors.New("invalid credentials JSON")
	}
	if err := snapshot.validate(cfg); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func uniqueJSONKeys(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name := key.(string)
			if seen[name] {
				return errors.New("duplicate JSON key")
			}
			seen[name] = true
			if err := uniqueJSONKeys(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
	case json.Delim('['):
		for dec.More() {
			if err := uniqueJSONKeys(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
	}
	return err
}

func (s *credentialSnapshot) validate(cfg config.Config) error {
	clientIDs := make(map[string]bool, len(cfg.Clients))
	for _, client := range cfg.Clients {
		clientIDs[client.ID] = true
	}
	for id := range s.Clients {
		if !clientIDs[id] {
			return errors.New("credentials contain an unknown client")
		}
	}
	backendTools := make(map[string]bool)
	for _, tool := range cfg.Tools {
		if tool.BackendTokenRequired || tool.BackendTokenEnv != "" {
			backendTools[tool.Name] = true
		}
	}
	for name := range s.Backends {
		if !backendTools[name] {
			return errors.New("credentials contain an unknown or unauthenticated backend")
		}
	}

	owners := make(map[string]string)
	for _, client := range cfg.Clients {
		for i := range s.Clients[client.ID] {
			credential := &s.Clients[client.ID][i]
			if err := credential.validate(32); err != nil {
				return fmt.Errorf("client %q credential: %w", client.ID, err)
			}
			if owner, exists := owners[credential.Token]; exists {
				return fmt.Errorf("%s and client %q must use distinct bearer tokens", owner, client.ID)
			}
			owners[credential.Token] = fmt.Sprintf("client %q", client.ID)
		}
	}
	for i := range s.Metrics {
		credential := &s.Metrics[i]
		if err := credential.validate(32); err != nil {
			return fmt.Errorf("metrics credential: %w", err)
		}
		if _, exists := owners[credential.Token]; exists {
			return errors.New("metrics credentials must be distinct from client and other metrics tokens")
		}
		owners[credential.Token] = "metrics"
	}
	for name, credential := range s.Backends {
		if err := credential.validate(1); err != nil {
			return errors.New("invalid backend credential")
		}
		if _, exists := owners[credential.Token]; exists {
			return errors.New("backend credentials must be distinct from gateway authentication tokens")
		}
		s.Backends[name] = credential
	}
	return nil
}

func (c *tokenCredential) validate(minLength int) error {
	c.Token = strings.TrimSpace(c.Token)
	if len(c.Token) < minLength || !bearerTokenPattern.MatchString(c.Token) {
		return errors.New("token has invalid length or bearer syntax")
	}
	if !c.ExpiresAt.IsZero() && !c.NotBefore.IsZero() && !c.ExpiresAt.After(c.NotBefore) {
		return errors.New("expires_at must be after not_before")
	}
	return nil
}

func (g *Gateway) ReloadCredentials() error {
	if g.cfg.CredentialsFile == "" {
		return errors.New("credential reload requires credentials_file; environment credentials require a restart")
	}
	g.reloadMu.Lock()
	defer g.reloadMu.Unlock()
	snapshot, err := loadCredentialFile(g.cfg)
	if err != nil {
		return err
	}
	g.secrets.Store(snapshot)
	return nil
}
