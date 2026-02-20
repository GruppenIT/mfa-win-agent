package idp

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/auth"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/config"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/events"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/idp/oidc"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/idp/saml"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/idp/session"
)

// Server is the IdP HTTPS server.
type Server struct {
	cfg       *config.IdPConfig
	cert      *x509.Certificate
	key       *rsa.PrivateKey
	sessions  *session.Store
	reporter  *events.Reporter
	httpSrv   *http.Server
}

// NewServer creates a new IdP HTTP server.
func NewServer(
	cfg *config.IdPConfig,
	cert *x509.Certificate,
	key *rsa.PrivateKey,
	ldapAuth *auth.LDAPAuthenticator,
	totpVal *auth.TOTPValidator,
	reporter *events.Reporter,
) (*Server, error) {
	sessions := session.NewStore(cfg.SessionTimeout)

	// Parse login template: try loading from file, fall back to built-in
	tmplStr := fallbackTemplate
	if data, err := os.ReadFile("/etc/mfa-gruppen/templates/login.html"); err == nil {
		tmplStr = string(data)
		slog.Info("loaded custom login template from /etc/mfa-gruppen/templates/login.html")
	}
	loginTmpl, err := template.New("login").Parse(tmplStr)
	if err != nil {
		return nil, fmt.Errorf("parsing login template: %w", err)
	}

	// Build assertion builder
	builder := saml.NewAssertionBuilder(cfg.EntityID, cert, key)

	// Build SSO handler
	ssoHandler := saml.NewSSOHandler(
		cfg.EntityID,
		cfg.TrustedSPs,
		ldapAuth,
		totpVal,
		sessions,
		builder,
		reporter,
		loginTmpl,
	)

	// Determine base URL from entity ID or construct from port
	baseURL := cfg.EntityID

	// Set up routes
	mux := http.NewServeMux()

	// SAML endpoints
	mux.HandleFunc("GET /saml/metadata", func(w http.ResponseWriter, r *http.Request) {
		reporter.Report(events.Event{
			Type: events.EventIDPMetadataReq,
			Data: map[string]string{
				"client_ip": r.RemoteAddr,
			},
		})
		metadataXML, err := saml.GenerateMetadata(cfg.EntityID, baseURL, cert)
		if err != nil {
			slog.Error("failed to generate metadata", "error", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.Write(metadataXML)
	})

	mux.HandleFunc("GET /saml/sso", ssoHandler.HandleSSO)
	mux.HandleFunc("POST /saml/sso", ssoHandler.HandleSSO)
	mux.HandleFunc("GET /saml/slo", ssoHandler.HandleSLO)
	mux.HandleFunc("POST /saml/slo", ssoHandler.HandleSLO)

	// Health endpoint
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","module":"idp","sessions":%d}`, sessions.ActiveCount())
	})

	// OIDC stubs (Phase 2)
	oidc.RegisterRoutes(mux, cfg.EntityID)

	srv := &Server{
		cfg:      cfg,
		cert:     cert,
		key:      key,
		sessions: sessions,
		reporter: reporter,
		httpSrv: &http.Server{
			Addr:         fmt.Sprintf(":%d", cfg.Port),
			Handler:      mux,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
	}

	return srv, nil
}

// Start begins listening on the configured HTTPS port.
func (s *Server) Start(ctx context.Context, done <-chan struct{}) error {
	s.sessions.StartCleanup(done)

	slog.Info("IdP server starting", "port", s.cfg.Port)
	return s.httpSrv.ListenAndServeTLS(s.cfg.TLS.Cert, s.cfg.TLS.Key)
}

// Stop gracefully shuts down the IdP server.
func (s *Server) Stop(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

// Sessions returns the session store (for heartbeat reporting).
func (s *Server) Sessions() *session.Store {
	return s.sessions
}

// CertNotAfter returns the certificate expiration time.
func (s *Server) CertNotAfter() time.Time {
	return s.cert.NotAfter
}

const fallbackTemplate = `<!DOCTYPE html>
<html>
<head><title>MFA Gruppen - Sign In</title></head>
<body>
<h1>MFA Gruppen - Sign In</h1>
{{if .SPName}}<p>Signing in to <strong>{{.SPName}}</strong></p>{{end}}
{{if .Error}}<p style="color:red">{{.Error}}</p>{{end}}
<form method="POST" action="/saml/sso">
<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}"/>
<input type="hidden" name="RelayState" value="{{.RelayState}}"/>
<p><label>Username: <input name="username" required/></label></p>
<p><label>Password: <input type="password" name="password" required/></label></p>
<p><label>TOTP Code: <input name="totp_code" pattern="[0-9]{6,8}" required/></label></p>
<button type="submit">Sign In</button>
</form>
</body>
</html>`
