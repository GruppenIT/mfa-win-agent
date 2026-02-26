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
)

func testCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
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
	return cert
}

func TestGenerateMetadata(t *testing.T) {
	cert := testCert(t)
	entityID := "https://idp.example.com/saml"
	baseURL := "https://idp.example.com"

	data, err := GenerateMetadata(entityID, baseURL, cert)
	if err != nil {
		t.Fatalf("GenerateMetadata failed: %v", err)
	}

	xmlStr := string(data)

	// Check XML declaration
	if !strings.HasPrefix(xmlStr, "<?xml") {
		t.Error("missing XML declaration")
	}

	// Check it's valid XML
	var descriptor EntityDescriptor
	if err := xml.Unmarshal(data[strings.Index(xmlStr, "<EntityDescriptor"):], &descriptor); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}

	// Check EntityID
	if descriptor.EntityID != entityID {
		t.Errorf("expected entityID '%s', got '%s'", entityID, descriptor.EntityID)
	}

	// Check SSO endpoints
	ssoServices := descriptor.IDPSSODescriptor.SingleSignOnServices
	if len(ssoServices) != 2 {
		t.Fatalf("expected 2 SSO services, got %d", len(ssoServices))
	}

	foundRedirect := false
	foundPost := false
	for _, svc := range ssoServices {
		if svc.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" {
			foundRedirect = true
			if svc.Location != "https://idp.example.com/saml/sso" {
				t.Errorf("unexpected redirect location: %s", svc.Location)
			}
		}
		if svc.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" {
			foundPost = true
		}
	}
	if !foundRedirect {
		t.Error("missing HTTP-Redirect binding")
	}
	if !foundPost {
		t.Error("missing HTTP-POST binding")
	}

	// Check signing key is present
	if len(descriptor.IDPSSODescriptor.KeyDescriptors) == 0 {
		t.Error("missing key descriptors")
	}
	if descriptor.IDPSSODescriptor.KeyDescriptors[0].Use != "signing" {
		t.Error("expected signing key descriptor")
	}
	if descriptor.IDPSSODescriptor.KeyDescriptors[0].KeyInfo.X509Data.X509Certificate == "" {
		t.Error("missing X509 certificate in metadata")
	}

	// Check NameID formats
	if len(descriptor.IDPSSODescriptor.NameIDFormats) < 1 {
		t.Error("missing NameID formats")
	}
}
