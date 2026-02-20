package radius

import (
	"context"
	"fmt"
	"log/slog"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"

	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/auth"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/events"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/logging"
)

// Server implements a RADIUS authentication server.
type Server struct {
	port      int
	secret    string
	totp      *auth.TOTPValidator
	ldap      *auth.LDAPAuthenticator
	reporter  *events.Reporter
	server    *radius.PacketServer
}

// NewServer creates a new RADIUS server.
func NewServer(port int, secret string, totp *auth.TOTPValidator, ldapAuth *auth.LDAPAuthenticator, reporter *events.Reporter) *Server {
	return &Server{
		port:     port,
		secret:   secret,
		totp:     totp,
		ldap:     ldapAuth,
		reporter: reporter,
	}
}

// Start begins listening on the RADIUS port.
func (s *Server) Start(ctx context.Context) error {
	handler := radius.HandlerFunc(func(w radius.ResponseWriter, r *radius.Request) {
		s.handleRequest(ctx, w, r)
	})

	addr := fmt.Sprintf(":%d", s.port)
	s.server = &radius.PacketServer{
		Addr:         addr,
		Handler:      handler,
		SecretSource: radius.StaticSecretSource([]byte(s.secret)),
	}

	slog.Info("RADIUS server starting", "port", s.port)
	return s.server.ListenAndServe()
}

// Stop gracefully shuts down the RADIUS server.
func (s *Server) Stop() error {
	if s.server != nil {
		return s.server.Shutdown(context.Background())
	}
	return nil
}

func (s *Server) handleRequest(ctx context.Context, w radius.ResponseWriter, r *radius.Request) {
	ctx = logging.WithRequestID(ctx)
	log := logging.Logger(ctx)

	username := rfc2865.UserName_GetString(r.Packet)
	password := rfc2865.UserPassword_GetString(r.Packet)
	nasIP := rfc2865.NASIPAddress_Get(r.Packet)

	log.Info("RADIUS auth request", "username", username, "nas_ip", nasIP)

	if username == "" || password == "" {
		log.Warn("RADIUS request missing credentials")
		_ = w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// Password format: ADpassword + TOTPcode
	// The TOTP code is the last 6 (or 8) digits
	adPassword, totpCode := splitPasswordTOTP(password)

	// Step 1: Validate AD/LDAP credentials (if LDAP is configured)
	if s.ldap != nil {
		_, err := s.ldap.Authenticate(ctx, username, adPassword)
		if err != nil {
			log.Warn("RADIUS LDAP auth failed", "username", username, "error", err)
			s.reporter.Report(events.Event{
				Type: events.EventRADIUSAuthFailure,
				Data: map[string]string{
					"username": username,
					"reason":   "ldap_auth_failed",
					"nas_ip":   nasIP.String(),
				},
			})
			_ = w.Write(r.Response(radius.CodeAccessReject))
			return
		}
	}

	// Step 2: Validate TOTP
	result, err := s.totp.Validate(ctx, username, "", totpCode)
	if err != nil {
		log.Error("RADIUS TOTP validation error", "username", username, "error", err)
		s.reporter.Report(events.Event{
			Type: events.EventRADIUSAuthFailure,
			Data: map[string]string{
				"username": username,
				"reason":   "totp_validation_error",
				"nas_ip":   nasIP.String(),
			},
		})
		_ = w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	if !result.Success {
		log.Warn("RADIUS TOTP validation failed", "username", username)
		s.reporter.Report(events.Event{
			Type: events.EventRADIUSAuthFailure,
			Data: map[string]string{
				"username": username,
				"reason":   "totp_invalid",
				"nas_ip":   nasIP.String(),
			},
		})
		_ = w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	log.Info("RADIUS auth success", "username", username)
	s.reporter.Report(events.Event{
		Type: events.EventRADIUSAuthSuccess,
		Data: map[string]string{
			"username": username,
			"nas_ip":   nasIP.String(),
		},
	})
	_ = w.Write(r.Response(radius.CodeAccessAccept))
}

// splitPasswordTOTP splits a concatenated password+TOTP string.
// Tries 6-digit TOTP first, then 8-digit.
func splitPasswordTOTP(combined string) (password, totp string) {
	if len(combined) <= 6 {
		return "", combined
	}
	// Assume 6-digit TOTP by default
	totpLen := 6
	if len(combined) > 8 {
		// Check if the last 8 chars are all digits
		last8 := combined[len(combined)-8:]
		allDigits := true
		for _, c := range last8 {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			// Could be 8-digit TOTP; still default to 6 unless configured otherwise
			_ = last8
		}
	}
	return combined[:len(combined)-totpLen], combined[len(combined)-totpLen:]
}
