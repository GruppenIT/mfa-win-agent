package saml

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"html/template"
	"net/http"

	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/auth"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/config"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/events"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/idp/session"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/logging"
)

// SSOHandler handles SAML SSO requests.
type SSOHandler struct {
	entityID   string
	trustedSPs map[string]*config.TrustedSP
	ldap       *auth.LDAPAuthenticator
	totp       *auth.TOTPValidator
	sessions   *session.Store
	builder    *AssertionBuilder
	reporter   *events.Reporter
	loginTmpl  *template.Template
}

// NewSSOHandler creates a new SSO handler.
func NewSSOHandler(
	entityID string,
	trustedSPs []config.TrustedSP,
	ldap *auth.LDAPAuthenticator,
	totp *auth.TOTPValidator,
	sessions *session.Store,
	builder *AssertionBuilder,
	reporter *events.Reporter,
	loginTmpl *template.Template,
) *SSOHandler {
	spMap := make(map[string]*config.TrustedSP, len(trustedSPs))
	for i := range trustedSPs {
		spMap[trustedSPs[i].EntityID] = &trustedSPs[i]
	}
	return &SSOHandler{
		entityID:   entityID,
		trustedSPs: spMap,
		ldap:       ldap,
		totp:       totp,
		sessions:   sessions,
		builder:    builder,
		reporter:   reporter,
		loginTmpl:  loginTmpl,
	}
}

// HandleSSO processes SAML SSO requests (both GET redirect and POST bindings).
func (h *SSOHandler) HandleSSO(w http.ResponseWriter, r *http.Request) {
	ctx := logging.WithRequestID(r.Context())
	log := logging.Logger(ctx)

	var authnReq *AuthnRequest
	var relayState string
	var err error

	switch r.Method {
	case http.MethodGet:
		// HTTP-Redirect binding
		samlReq := r.URL.Query().Get("SAMLRequest")
		relayState = r.URL.Query().Get("RelayState")
		if samlReq == "" {
			http.Error(w, "Missing SAMLRequest parameter", http.StatusBadRequest)
			return
		}
		authnReq, err = ParseAuthnRequest(samlReq)
	case http.MethodPost:
		// Could be HTTP-POST binding or login form submission
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		// Check if this is a login form submission
		if r.Form.Get("username") != "" {
			h.handleLogin(ctx, w, r)
			return
		}

		// HTTP-POST binding
		samlReq := r.Form.Get("SAMLRequest")
		relayState = r.Form.Get("RelayState")
		if samlReq == "" {
			http.Error(w, "Missing SAMLRequest parameter", http.StatusBadRequest)
			return
		}
		authnReq, err = ParseAuthnRequestPOST(samlReq)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		log.Error("failed to parse AuthnRequest", "error", err)
		http.Error(w, "Invalid SAMLRequest", http.StatusBadRequest)
		return
	}

	log.Info("received AuthnRequest",
		"request_id", authnReq.ID,
		"issuer", authnReq.Issuer.Value,
	)

	// Validate SP is trusted
	sp, ok := h.trustedSPs[authnReq.Issuer.Value]
	if !ok {
		log.Warn("untrusted SP", "entity_id", authnReq.Issuer.Value)
		http.Error(w, "Untrusted Service Provider", http.StatusForbidden)
		return
	}

	// Re-encode the AuthnRequest for the login form (as base64 XML)
	authnReqXML, err := reencodeAuthnRequest(authnReq)
	if err != nil {
		log.Error("failed to re-encode AuthnRequest", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Show login page
	h.renderLoginPage(w, authnReqXML, relayState, sp.Name, "")
}

// handleLogin processes the login form submission.
func (h *SSOHandler) handleLogin(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	log := logging.Logger(ctx)

	username := r.Form.Get("username")
	password := r.Form.Get("password")
	totpCode := r.Form.Get("totp_code")
	samlReqB64 := r.Form.Get("SAMLRequest")
	relayState := r.Form.Get("RelayState")

	// Re-parse the stored AuthnRequest
	authnReq, err := ParseAuthnRequestPOST(samlReqB64)
	if err != nil {
		log.Error("failed to parse stored AuthnRequest", "error", err)
		http.Error(w, "Invalid session state", http.StatusBadRequest)
		return
	}

	sp, ok := h.trustedSPs[authnReq.Issuer.Value]
	if !ok {
		http.Error(w, "Untrusted Service Provider", http.StatusForbidden)
		return
	}

	clientIP := r.RemoteAddr

	// Step 1: Validate AD/LDAP credentials
	ldapUser, err := h.ldap.Authenticate(ctx, username, password)
	if err != nil {
		log.Warn("LDAP authentication failed", "username", username, "error", err)
		h.reporter.Report(events.Event{
			Type: events.EventIDPAuthFailure,
			Data: map[string]string{
				"username":  username,
				"sp":        sp.Name,
				"reason":    "ldap_auth_failed",
				"client_ip": clientIP,
			},
		})
		h.renderLoginPage(w, samlReqB64, relayState, sp.Name, "Invalid username or password")
		return
	}

	// Step 2: Validate TOTP
	totpResult, err := h.totp.Validate(ctx, username, "", totpCode)
	if err != nil {
		log.Error("TOTP validation error", "username", username, "error", err)
		h.reporter.Report(events.Event{
			Type: events.EventIDPAuthFailure,
			Data: map[string]string{
				"username":  username,
				"sp":        sp.Name,
				"reason":    "totp_validation_error",
				"client_ip": clientIP,
			},
		})
		h.renderLoginPage(w, samlReqB64, relayState, sp.Name, "Authentication service error. Please try again.")
		return
	}

	if !totpResult.Success {
		log.Warn("TOTP validation failed", "username", username)
		h.reporter.Report(events.Event{
			Type: events.EventIDPAuthTOTPFailure,
			Data: map[string]string{
				"username":  username,
				"sp":        sp.Name,
				"reason":    "totp_invalid",
				"client_ip": clientIP,
			},
		})
		h.renderLoginPage(w, samlReqB64, relayState, sp.Name, "Invalid TOTP code")
		return
	}

	// Authentication successful - create session
	sess := h.sessions.Create(
		ldapUser.Username,
		ldapUser.DisplayName,
		ldapUser.Email,
		ldapUser.UPN,
		ldapUser.Groups,
		sp.EntityID,
	)

	log.Info("authentication successful",
		"username", username,
		"sp", sp.Name,
		"session_id", sess.ID,
	)

	h.reporter.Report(events.Event{
		Type: events.EventIDPAuthSuccess,
		Data: map[string]string{
			"username":   username,
			"sp":         sp.Name,
			"session_id": sess.ID,
			"client_ip":  clientIP,
		},
	})
	h.reporter.Report(events.Event{
		Type: events.EventIDPSessionCreated,
		Data: map[string]string{
			"username":   username,
			"sp":         sp.Name,
			"session_id": sess.ID,
		},
	})

	// Build SAML Response
	samlResponse, err := h.builder.BuildResponse(authnReq, sess, sp)
	if err != nil {
		log.Error("failed to build SAML response", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Determine ACS URL
	acsURL := authnReq.AssertionConsumerServiceURL
	if acsURL == "" {
		acsURL = sp.ACSURL
	}

	// Encode response as base64 for POST binding
	samlResponseB64 := base64.StdEncoding.EncodeToString(samlResponse)

	// Send auto-submitting form to SP's ACS
	h.renderPostBinding(w, acsURL, samlResponseB64, relayState)
}

func (h *SSOHandler) renderLoginPage(w http.ResponseWriter, samlReqB64, relayState, spName, errMsg string) {
	data := map[string]string{
		"SAMLRequest": samlReqB64,
		"RelayState":  relayState,
		"SPName":      spName,
		"Error":       errMsg,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.loginTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func (h *SSOHandler) renderPostBinding(w http.ResponseWriter, acsURL, samlResponse, relayState string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
<noscript><p>JavaScript is required. Please click the button below.</p></noscript>
<form method="POST" action="%s">
<input type="hidden" name="SAMLResponse" value="%s"/>
<input type="hidden" name="RelayState" value="%s"/>
<noscript><input type="submit" value="Continue"/></noscript>
</form>
</body>
</html>`, template.HTMLEscapeString(acsURL), samlResponse, template.HTMLEscapeString(relayState))
}

func reencodeAuthnRequest(req *AuthnRequest) (string, error) {
	data, err := marshalAuthnRequest(req)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func marshalAuthnRequest(req *AuthnRequest) ([]byte, error) {
	return xml.Marshal(req)
}

// HandleSLO handles Single Logout requests (stub for phase 1).
func (h *SSOHandler) HandleSLO(w http.ResponseWriter, r *http.Request) {
	ctx := logging.WithRequestID(r.Context())
	log := logging.Logger(ctx)

	log.Info("SLO request received (not fully implemented)")

	h.reporter.Report(events.Event{
		Type: events.EventIDPSLORequested,
		Data: map[string]string{
			"method": r.Method,
		},
	})

	http.Error(w, "Single Logout not yet implemented", http.StatusNotImplemented)
}
