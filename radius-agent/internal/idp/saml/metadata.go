package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
)

// EntityDescriptor represents the SAML IdP metadata.
type EntityDescriptor struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID string   `xml:"entityID,attr"`
	IDPSSODescriptor IDPSSODescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
}

// IDPSSODescriptor describes the IdP capabilities.
type IDPSSODescriptor struct {
	XMLName                    xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	ProtocolSupportEnumeration string                `xml:"protocolSupportEnumeration,attr"`
	WantAuthnRequestsSigned    bool                  `xml:"WantAuthnRequestsSigned,attr"`
	KeyDescriptors             []KeyDescriptor       `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	SingleSignOnServices       []SingleSignOnService `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
	SingleLogoutServices       []SingleLogoutService `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService"`
	NameIDFormats              []NameIDFormat        `xml:"urn:oasis:names:tc:SAML:2.0:metadata NameIDFormat"`
}

// KeyDescriptor holds the signing certificate info.
type KeyDescriptor struct {
	Use     string  `xml:"use,attr"`
	KeyInfo KeyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

// KeyInfo wraps X509Data.
type KeyInfo struct {
	X509Data X509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

// X509Data wraps the certificate.
type X509Data struct {
	X509Certificate string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

// SingleSignOnService describes the SSO binding endpoint.
type SingleSignOnService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

// SingleLogoutService describes the SLO binding endpoint.
type SingleLogoutService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

// NameIDFormat specifies the supported NameID format.
type NameIDFormat struct {
	Format string `xml:",chardata"`
}

// GenerateMetadata creates the SAML metadata XML for this IdP.
func GenerateMetadata(entityID, baseURL string, cert *x509.Certificate) ([]byte, error) {
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	descriptor := EntityDescriptor{
		EntityID: entityID,
		IDPSSODescriptor: IDPSSODescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			WantAuthnRequestsSigned:    false,
			KeyDescriptors: []KeyDescriptor{
				{
					Use: "signing",
					KeyInfo: KeyInfo{
						X509Data: X509Data{
							X509Certificate: certB64,
						},
					},
				},
			},
			SingleSignOnServices: []SingleSignOnService{
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
					Location: fmt.Sprintf("%s/saml/sso", baseURL),
				},
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: fmt.Sprintf("%s/saml/sso", baseURL),
				},
			},
			SingleLogoutServices: []SingleLogoutService{
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
					Location: fmt.Sprintf("%s/saml/slo", baseURL),
				},
			},
			NameIDFormats: []NameIDFormat{
				{Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"},
				{Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"},
				{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"},
			},
		},
	}

	output, err := xml.MarshalIndent(descriptor, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling metadata: %w", err)
	}

	// Prepend XML declaration
	xmlDecl := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	return append(xmlDecl, output...), nil
}
