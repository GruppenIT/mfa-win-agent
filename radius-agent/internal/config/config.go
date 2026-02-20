package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server  ServerConfig  `yaml:"server"`
	RADIUS  RADIUSConfig  `yaml:"radius"`
	IdP     IdPConfig     `yaml:"idp"`
	API     APIConfig     `yaml:"api"`
	Logging LoggingConfig `yaml:"logging"`
}

type ServerConfig struct {
	AgentID string `yaml:"agent_id"`
}

type APIConfig struct {
	BaseURL string `yaml:"base_url"`
	Key     string `yaml:"key"`
	Timeout int    `yaml:"timeout"` // seconds
}

type RADIUSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Secret  string `yaml:"secret"`
	LDAP    *LDAPConfig `yaml:"ldap"`
}

type IdPConfig struct {
	Enabled        bool             `yaml:"enabled"`
	Port           int              `yaml:"port"`
	TLS            TLSConfig        `yaml:"tls"`
	EntityID       string           `yaml:"entity_id"`
	SessionTimeout int              `yaml:"session_timeout"` // seconds
	TrustedSPs     []TrustedSP      `yaml:"trusted_sps"`
	LDAP           *IdPLDAPConfig   `yaml:"ldap"`
}

type TLSConfig struct {
	Cert         string `yaml:"cert"`
	Key          string `yaml:"key"`
	AutoGenerate bool   `yaml:"auto_generate"`
}

type TrustedSP struct {
	Name       string          `yaml:"name"`
	EntityID   string          `yaml:"entity_id"`
	ACSURL     string          `yaml:"acs_url"`
	Attributes []SPAttribute   `yaml:"attributes"`
}

type SPAttribute struct {
	Name   string `yaml:"name"`
	Source string `yaml:"source"`
}

type IdPLDAPConfig struct {
	UseRADIUSConfig bool   `yaml:"use_radius_config"`
	Server          string `yaml:"server"`
	BaseDN          string `yaml:"base_dn"`
	BindDN          string `yaml:"bind_dn"`
	BindPassword    string `yaml:"bind_password"`
	UserFilter      string `yaml:"user_filter"`
	TLS             bool   `yaml:"tls"`
	StartTLS        bool   `yaml:"starttls"`
}

type LDAPConfig struct {
	Server       string `yaml:"server"`
	BaseDN       string `yaml:"base_dn"`
	BindDN       string `yaml:"bind_dn"`
	BindPassword string `yaml:"bind_password"`
	UserFilter   string `yaml:"user_filter"`
	TLS          bool   `yaml:"tls"`
	StartTLS     bool   `yaml:"starttls"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"` // debug, info, warn, error
	Format string `yaml:"format"` // json, text
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	applyDefaults(cfg)

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.RADIUS.Port == 0 {
		cfg.RADIUS.Port = 1812
	}
	if cfg.IdP.Port == 0 {
		cfg.IdP.Port = 8443
	}
	if cfg.IdP.SessionTimeout == 0 {
		cfg.IdP.SessionTimeout = 3600
	}
	if cfg.API.Timeout == 0 {
		cfg.API.Timeout = 30
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}
	if cfg.IdP.TLS.Cert == "" {
		cfg.IdP.TLS.Cert = "/etc/mfa-gruppen/certs/idp.crt"
	}
	if cfg.IdP.TLS.Key == "" {
		cfg.IdP.TLS.Key = "/etc/mfa-gruppen/certs/idp.key"
	}
}

func validate(cfg *Config) error {
	if !cfg.RADIUS.Enabled && !cfg.IdP.Enabled {
		return fmt.Errorf("at least one module (radius or idp) must be enabled")
	}
	if cfg.API.BaseURL == "" {
		return fmt.Errorf("api.base_url is required")
	}
	if cfg.API.Key == "" {
		return fmt.Errorf("api.key is required")
	}
	if cfg.IdP.Enabled {
		if cfg.IdP.EntityID == "" {
			return fmt.Errorf("idp.entity_id is required when IdP is enabled")
		}
		if len(cfg.IdP.TrustedSPs) == 0 {
			return fmt.Errorf("at least one trusted SP is required when IdP is enabled")
		}
		for i, sp := range cfg.IdP.TrustedSPs {
			if sp.EntityID == "" {
				return fmt.Errorf("idp.trusted_sps[%d].entity_id is required", i)
			}
			if sp.ACSURL == "" {
				return fmt.Errorf("idp.trusted_sps[%d].acs_url is required", i)
			}
		}
	}
	if cfg.RADIUS.Enabled && cfg.RADIUS.Secret == "" {
		return fmt.Errorf("radius.secret is required when RADIUS is enabled")
	}
	return nil
}

// ResolveLDAP returns the effective LDAP config for the IdP module,
// resolving the use_radius_config option.
func (cfg *Config) ResolveLDAP() *LDAPConfig {
	if cfg.IdP.LDAP != nil && !cfg.IdP.LDAP.UseRADIUSConfig {
		return &LDAPConfig{
			Server:       cfg.IdP.LDAP.Server,
			BaseDN:       cfg.IdP.LDAP.BaseDN,
			BindDN:       cfg.IdP.LDAP.BindDN,
			BindPassword: cfg.IdP.LDAP.BindPassword,
			UserFilter:   cfg.IdP.LDAP.UserFilter,
			TLS:          cfg.IdP.LDAP.TLS,
			StartTLS:     cfg.IdP.LDAP.StartTLS,
		}
	}
	if cfg.RADIUS.LDAP != nil {
		return cfg.RADIUS.LDAP
	}
	return nil
}
