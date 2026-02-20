package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/config"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/idp/session"
)

func testKeyPair(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test IdP"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestBuildResponse(t *testing.T) {
	cert, key := testKeyPair(t)
	builder := NewAssertionBuilder("https://idp.example.com/saml", cert, key)

	authnReq := &AuthnRequest{
		ID:                          "_request123",
		Version:                     "2.0",
		IssueInstant:                "2026-02-20T10:00:00Z",
		Issuer:                      Issuer{Value: "https://sp.example.com"},
		AssertionConsumerServiceURL: "https://sp.example.com/acs",
	}

	sess := &session.Session{
		ID:          "session-001",
		Username:    "john.doe",
		DisplayName: "John Doe",
		Email:       "john@example.com",
		UPN:         "john.doe@example.com",
		Groups:      []string{"Admins", "Users"},
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	sp := &config.TrustedSP{
		Name:     "TestSP",
		EntityID: "https://sp.example.com",
		ACSURL:   "https://sp.example.com/acs",
		Attributes: []config.SPAttribute{
			{Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", Source: "upn"},
			{Name: "http://schemas.xmlsoap.org/claims/Group", Source: "memberOf"},
		},
	}

	responseXML, err := builder.BuildResponse(authnReq, sess, sp)
	if err != nil {
		t.Fatalf("BuildResponse failed: %v", err)
	}

	xmlStr := string(responseXML)

	// Verify it's valid XML
	var resp Response
	if err := xml.Unmarshal(responseXML, &resp); err != nil {
		t.Fatalf("response is not valid XML: %v", err)
	}

	// Check InResponseTo
	if resp.InResponseTo != "_request123" {
		t.Errorf("expected InResponseTo '_request123', got '%s'", resp.InResponseTo)
	}

	// Check Destination
	if resp.Destination != "https://sp.example.com/acs" {
		t.Errorf("expected Destination ACS URL, got '%s'", resp.Destination)
	}

	// Check Issuer
	if resp.RespIssuer.Value != "https://idp.example.com/saml" {
		t.Errorf("expected Issuer, got '%s'", resp.RespIssuer.Value)
	}

	// Check Status
	if resp.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		t.Errorf("expected Success status, got '%s'", resp.Status.StatusCode.Value)
	}

	// Check assertion has signature
	if resp.Assertion.Signature == nil {
		t.Error("expected signed assertion")
	}

	// Check NameID contains UPN
	if resp.Assertion.Subject.NameID.Value != "john.doe@example.com" {
		t.Errorf("expected NameID 'john.doe@example.com', got '%s'", resp.Assertion.Subject.NameID.Value)
	}

	// Check audience restriction
	if resp.Assertion.Conditions.AudienceRestriction.Audience != "https://sp.example.com" {
		t.Errorf("expected audience 'https://sp.example.com', got '%s'",
			resp.Assertion.Conditions.AudienceRestriction.Audience)
	}

	// Check attributes are present
	if resp.Assertion.AttrStmt == nil {
		t.Fatal("expected attribute statement")
	}
	if len(resp.Assertion.AttrStmt.Attributes) < 2 {
		t.Errorf("expected at least 2 attributes, got %d", len(resp.Assertion.AttrStmt.Attributes))
	}

	// Check UPN attribute
	foundUPN := false
	for _, attr := range resp.Assertion.AttrStmt.Attributes {
		if strings.Contains(attr.Name, "upn") {
			foundUPN = true
			if len(attr.Values) == 0 || attr.Values[0].Value != "john.doe@example.com" {
				t.Error("UPN attribute value incorrect")
			}
		}
	}
	if !foundUPN {
		t.Error("UPN attribute not found")
	}

	// Check that the XML contains the group attribute
	if !strings.Contains(xmlStr, "Admins") || !strings.Contains(xmlStr, "Users") {
		t.Error("group attributes not found in response XML")
	}
}

func TestBuildResponse_FallbackACSURL(t *testing.T) {
	cert, key := testKeyPair(t)
	builder := NewAssertionBuilder("https://idp.example.com/saml", cert, key)

	// AuthnRequest without ACS URL
	authnReq := &AuthnRequest{
		ID:      "_req456",
		Version: "2.0",
		Issuer:  Issuer{Value: "https://sp.example.com"},
	}

	sess := &session.Session{
		ID:       "session-002",
		Username: "jane.doe",
		UPN:      "jane.doe@example.com",
	}

	sp := &config.TrustedSP{
		EntityID: "https://sp.example.com",
		ACSURL:   "https://sp.example.com/fallback-acs",
	}

	responseXML, err := builder.BuildResponse(authnReq, sess, sp)
	if err != nil {
		t.Fatalf("BuildResponse failed: %v", err)
	}

	var resp Response
	xml.Unmarshal(responseXML, &resp)

	if resp.Destination != "https://sp.example.com/fallback-acs" {
		t.Errorf("expected fallback ACS URL, got '%s'", resp.Destination)
	}
}
