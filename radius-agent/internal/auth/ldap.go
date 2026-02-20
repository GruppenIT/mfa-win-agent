package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/config"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/logging"
	"github.com/go-ldap/ldap/v3"
)

// LDAPUser holds information about an authenticated LDAP user.
type LDAPUser struct {
	DN          string
	Username    string
	DisplayName string
	Email       string
	UPN         string
	Groups      []string
}

// LDAPAuthenticator handles authentication against an AD/LDAP directory.
type LDAPAuthenticator struct {
	cfg *config.LDAPConfig
}

// NewLDAPAuthenticator creates a new LDAP authenticator from config.
func NewLDAPAuthenticator(cfg *config.LDAPConfig) *LDAPAuthenticator {
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(sAMAccountName=%s)"
	}
	return &LDAPAuthenticator{cfg: cfg}
}

// Authenticate validates username/password against LDAP and returns user info.
func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (*LDAPUser, error) {
	log := logging.Logger(ctx)

	conn, err := a.connect()
	if err != nil {
		return nil, fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()

	// Bind with service account to search for user
	if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("ldap service bind: %w", err)
	}

	// Search for user
	filter := fmt.Sprintf(a.cfg.UserFilter, ldap.EscapeFilter(username))
	searchReq := ldap.NewSearchRequest(
		a.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, // size limit
		30, // time limit seconds
		false,
		filter,
		[]string{"dn", "sAMAccountName", "displayName", "mail", "userPrincipalName", "memberOf"},
		nil,
	)

	log.Debug("searching LDAP for user", "filter", filter, "base_dn", a.cfg.BaseDN)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user not found: %s", username)
	}

	entry := sr.Entries[0]
	userDN := entry.DN

	// Bind as the user to verify password
	if err := conn.Bind(userDN, password); err != nil {
		return nil, fmt.Errorf("ldap user bind failed: %w", err)
	}

	log.Debug("LDAP authentication successful", "username", username, "dn", userDN)

	// Extract groups
	groups := make([]string, 0)
	for _, g := range entry.GetAttributeValues("memberOf") {
		groups = append(groups, extractCN(g))
	}

	return &LDAPUser{
		DN:          userDN,
		Username:    entry.GetAttributeValue("sAMAccountName"),
		DisplayName: entry.GetAttributeValue("displayName"),
		Email:       entry.GetAttributeValue("mail"),
		UPN:         entry.GetAttributeValue("userPrincipalName"),
		Groups:      groups,
	}, nil
}

func (a *LDAPAuthenticator) connect() (*ldap.Conn, error) {
	if a.cfg.TLS {
		return ldap.DialTLS("tcp", a.cfg.Server, &tls.Config{
			InsecureSkipVerify: false,
		})
	}

	conn, err := ldap.DialURL(a.cfg.Server)
	if err != nil {
		return nil, err
	}

	if a.cfg.StartTLS {
		if err := conn.StartTLS(&tls.Config{
			InsecureSkipVerify: false,
		}); err != nil {
			conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}

	return conn, nil
}

// extractCN extracts the CN value from a DN string.
func extractCN(dn string) string {
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return part[3:]
		}
	}
	return dn
}
