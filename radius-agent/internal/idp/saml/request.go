package saml

import (
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// AuthnRequest represents an incoming SAML AuthnRequest from an SP.
type AuthnRequest struct {
	XMLName                xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                     string   `xml:"ID,attr"`
	Version                string   `xml:"Version,attr"`
	IssueInstant           string   `xml:"IssueInstant,attr"`
	Destination            string   `xml:"Destination,attr"`
	AssertionConsumerServiceURL string `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding        string   `xml:"ProtocolBinding,attr"`
	Issuer                 Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameIDPolicy           *NameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
}

// Issuer represents the SAML Issuer element.
type Issuer struct {
	Value string `xml:",chardata"`
}

// NameIDPolicy represents the NameIDPolicy element.
type NameIDPolicy struct {
	Format string `xml:"Format,attr"`
}

// ParseAuthnRequest decodes and parses a SAML AuthnRequest from a redirect binding.
// The SAMLRequest parameter is base64+DEFLATE encoded.
func ParseAuthnRequest(samlRequest string) (*AuthnRequest, error) {
	// Base64 decode
	decoded, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		// Try URL-safe base64
		decoded, err = base64.RawURLEncoding.DecodeString(samlRequest)
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
	}

	// DEFLATE decompress
	reader := flate.NewReader(strings.NewReader(string(decoded)))
	defer reader.Close()

	xmlData, err := io.ReadAll(reader)
	if err != nil {
		// Maybe it's not deflated (POST binding sends plain base64)
		xmlData = decoded
	}

	return ParseAuthnRequestXML(xmlData)
}

// ParseAuthnRequestXML parses SAML AuthnRequest from raw XML bytes.
func ParseAuthnRequestXML(xmlData []byte) (*AuthnRequest, error) {
	var req AuthnRequest
	if err := xml.Unmarshal(xmlData, &req); err != nil {
		return nil, fmt.Errorf("xml unmarshal: %w", err)
	}

	if req.ID == "" {
		return nil, fmt.Errorf("AuthnRequest missing ID attribute")
	}
	if req.Issuer.Value == "" {
		return nil, fmt.Errorf("AuthnRequest missing Issuer")
	}

	return &req, nil
}

// ParseAuthnRequestPOST decodes a SAML AuthnRequest from HTTP-POST binding.
// The SAMLRequest is just base64 encoded (no DEFLATE).
func ParseAuthnRequestPOST(samlRequest string) (*AuthnRequest, error) {
	decoded, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return ParseAuthnRequestXML(decoded)
}
