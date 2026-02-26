package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"testing"
)

func TestParseAuthnRequestXML(t *testing.T) {
	xmlData := []byte(`<samlp:AuthnRequest
		xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
		ID="_abc123"
		Version="2.0"
		IssueInstant="2026-02-20T10:00:00Z"
		Destination="https://idp.example.com/saml/sso"
		AssertionConsumerServiceURL="https://sp.example.com/acs"
		ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
		<saml:Issuer>https://sp.example.com</saml:Issuer>
	</samlp:AuthnRequest>`)

	req, err := ParseAuthnRequestXML(xmlData)
	if err != nil {
		t.Fatalf("ParseAuthnRequestXML failed: %v", err)
	}

	if req.ID != "_abc123" {
		t.Errorf("expected ID '_abc123', got '%s'", req.ID)
	}
	if req.Issuer.Value != "https://sp.example.com" {
		t.Errorf("expected Issuer 'https://sp.example.com', got '%s'", req.Issuer.Value)
	}
	if req.AssertionConsumerServiceURL != "https://sp.example.com/acs" {
		t.Errorf("expected ACS URL, got '%s'", req.AssertionConsumerServiceURL)
	}
}

func TestParseAuthnRequestXML_MissingID(t *testing.T) {
	xmlData := []byte(`<samlp:AuthnRequest
		xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
		Version="2.0">
		<saml:Issuer>https://sp.example.com</saml:Issuer>
	</samlp:AuthnRequest>`)

	_, err := ParseAuthnRequestXML(xmlData)
	if err == nil {
		t.Fatal("expected error for missing ID")
	}
}

func TestParseAuthnRequestXML_MissingIssuer(t *testing.T) {
	xmlData := []byte(`<samlp:AuthnRequest
		xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		ID="_abc"
		Version="2.0">
	</samlp:AuthnRequest>`)

	_, err := ParseAuthnRequestXML(xmlData)
	if err == nil {
		t.Fatal("expected error for missing Issuer")
	}
}

func TestParseAuthnRequestPOST(t *testing.T) {
	xmlData := `<samlp:AuthnRequest
		xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
		ID="_post123"
		Version="2.0"
		IssueInstant="2026-02-20T10:00:00Z">
		<saml:Issuer>https://sp.example.com</saml:Issuer>
	</samlp:AuthnRequest>`

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))

	req, err := ParseAuthnRequestPOST(encoded)
	if err != nil {
		t.Fatalf("ParseAuthnRequestPOST failed: %v", err)
	}
	if req.ID != "_post123" {
		t.Errorf("expected ID '_post123', got '%s'", req.ID)
	}
}

func TestParseAuthnRequest_Deflated(t *testing.T) {
	xmlData := `<samlp:AuthnRequest
		xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
		ID="_deflated123"
		Version="2.0">
		<saml:Issuer>https://sp.example.com</saml:Issuer>
	</samlp:AuthnRequest>`

	// DEFLATE compress
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write([]byte(xmlData))
	w.Close()

	// Base64 encode
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())

	req, err := ParseAuthnRequest(encoded)
	if err != nil {
		t.Fatalf("ParseAuthnRequest (deflated) failed: %v", err)
	}
	if req.ID != "_deflated123" {
		t.Errorf("expected ID '_deflated123', got '%s'", req.ID)
	}
}
