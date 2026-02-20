package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ValidConfig(t *testing.T) {
	content := `
server:
  agent_id: "test-agent-123"
api:
  base_url: "https://mfa.example.com"
  key: "mfa_testkey123"
radius:
  enabled: true
  port: 1812
  secret: "testing123"
idp:
  enabled: true
  port: 8443
  entity_id: "https://idp.example.com/saml"
  tls:
    auto_generate: true
  trusted_sps:
    - name: "TestSP"
      entity_id: "https://sp.example.com"
      acs_url: "https://sp.example.com/acs"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if cfg.Server.AgentID != "test-agent-123" {
		t.Errorf("expected agent_id 'test-agent-123', got '%s'", cfg.Server.AgentID)
	}
	if cfg.API.BaseURL != "https://mfa.example.com" {
		t.Errorf("expected base_url, got '%s'", cfg.API.BaseURL)
	}
	if cfg.RADIUS.Port != 1812 {
		t.Errorf("expected port 1812, got %d", cfg.RADIUS.Port)
	}
	if cfg.IdP.Port != 8443 {
		t.Errorf("expected port 8443, got %d", cfg.IdP.Port)
	}
	if cfg.IdP.SessionTimeout != 3600 {
		t.Errorf("expected default session timeout 3600, got %d", cfg.IdP.SessionTimeout)
	}
}

func TestLoad_DefaultPorts(t *testing.T) {
	content := `
api:
  base_url: "https://mfa.example.com"
  key: "mfa_key"
radius:
  enabled: true
  secret: "s"
idp:
  enabled: true
  entity_id: "https://idp.example.com/saml"
  tls:
    auto_generate: true
  trusted_sps:
    - name: "SP"
      entity_id: "https://sp.example.com"
      acs_url: "https://sp.example.com/acs"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RADIUS.Port != 1812 {
		t.Errorf("expected default RADIUS port 1812, got %d", cfg.RADIUS.Port)
	}
	if cfg.IdP.Port != 8443 {
		t.Errorf("expected default IdP port 8443, got %d", cfg.IdP.Port)
	}
}

func TestLoad_MissingAPIKey(t *testing.T) {
	content := `
api:
  base_url: "https://mfa.example.com"
radius:
  enabled: true
  secret: "s"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(content), 0644)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing API key")
	}
}

func TestLoad_NoModulesEnabled(t *testing.T) {
	content := `
api:
  base_url: "https://mfa.example.com"
  key: "mfa_key"
radius:
  enabled: false
idp:
  enabled: false
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(content), 0644)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error when no modules are enabled")
	}
}

func TestLoad_IdPMissingEntityID(t *testing.T) {
	content := `
api:
  base_url: "https://mfa.example.com"
  key: "mfa_key"
idp:
  enabled: true
  trusted_sps:
    - name: "SP"
      entity_id: "https://sp.example.com"
      acs_url: "https://sp.example.com/acs"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(content), 0644)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing IdP entity_id")
	}
}

func TestResolveLDAP_UseRadiusConfig(t *testing.T) {
	cfg := &Config{
		RADIUS: RADIUSConfig{
			LDAP: &LDAPConfig{
				Server: "ldap://radius-ldap:389",
				BaseDN: "DC=test,DC=local",
			},
		},
		IdP: IdPConfig{
			LDAP: &IdPLDAPConfig{
				UseRADIUSConfig: true,
			},
		},
	}

	ldap := cfg.ResolveLDAP()
	if ldap == nil {
		t.Fatal("expected LDAP config to be resolved")
	}
	if ldap.Server != "ldap://radius-ldap:389" {
		t.Errorf("expected RADIUS LDAP server, got '%s'", ldap.Server)
	}
}

func TestResolveLDAP_UseIdPConfig(t *testing.T) {
	cfg := &Config{
		IdP: IdPConfig{
			LDAP: &IdPLDAPConfig{
				UseRADIUSConfig: false,
				Server:          "ldap://idp-ldap:389",
				BaseDN:          "DC=idp,DC=local",
			},
		},
	}

	ldap := cfg.ResolveLDAP()
	if ldap == nil {
		t.Fatal("expected LDAP config to be resolved")
	}
	if ldap.Server != "ldap://idp-ldap:389" {
		t.Errorf("expected IdP LDAP server, got '%s'", ldap.Server)
	}
}
