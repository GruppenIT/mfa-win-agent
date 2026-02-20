package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/config"
	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/idp/session"
)

// Response represents a SAML Response document.
type Response struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	XMLNS        string    `xml:"xmlns:saml,attr"`
	ID           string    `xml:"ID,attr"`
	Version      string    `xml:"Version,attr"`
	IssueInstant string    `xml:"IssueInstant,attr"`
	Destination  string    `xml:"Destination,attr"`
	InResponseTo string    `xml:"InResponseTo,attr"`
	RespIssuer   RespIssuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status       Status    `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Assertion    Assertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

// RespIssuer is the issuer in the SAML Response.
type RespIssuer struct {
	Value string `xml:",chardata"`
}

// Status contains the status code.
type Status struct {
	StatusCode StatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

// StatusCode holds the value.
type StatusCode struct {
	Value string `xml:"Value,attr"`
}

// Assertion is a SAML assertion.
type Assertion struct {
	XMLName      xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID           string            `xml:"ID,attr"`
	Version      string            `xml:"Version,attr"`
	IssueInstant string            `xml:"IssueInstant,attr"`
	AssIssuer    RespIssuer        `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *SignatureValue   `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`
	Subject      Subject           `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions   Conditions        `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AuthnStmt    AuthnStatement    `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	AttrStmt     *AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement,omitempty"`
}

// SignatureValue holds a pre-computed XML signature placeholder.
type SignatureValue struct {
	XMLName        xml.Name        `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	SignedInfo     SignedInfo      `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	SignatureVal   string          `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
	KeyInfoSig     KeyInfoSig     `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

// SignedInfo contains the digest and signature methods.
type SignedInfo struct {
	CanonicalizationMethod CanonicalizationMethod `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	SignatureMethod        SignatureMethod         `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Reference              Reference               `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
}

// CanonicalizationMethod specifies the canonicalization algorithm.
type CanonicalizationMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// SignatureMethod specifies the signature algorithm.
type SignatureMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// Reference points to the signed element.
type Reference struct {
	URI        string      `xml:"URI,attr"`
	Transforms Transforms `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`
	DigestMethod DigestMethod `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	DigestValue  string       `xml:"http://www.w3.org/2000/09/xmldsig# DigestValue"`
}

// Transforms holds transform algorithms.
type Transforms struct {
	Transform []Transform `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
}

// Transform specifies a transform algorithm.
type Transform struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// DigestMethod specifies the digest algorithm.
type DigestMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// KeyInfoSig wraps certificate data in signature.
type KeyInfoSig struct {
	X509Data X509DataSig `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

// X509DataSig wraps the certificate in signature.
type X509DataSig struct {
	X509Certificate string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

// Subject identifies the authenticated user.
type Subject struct {
	NameID             NameID             `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SubjectConfirmation SubjectConfirmation `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
}

// NameID holds the user's name identifier.
type NameID struct {
	Format string `xml:"Format,attr"`
	Value  string `xml:",chardata"`
}

// SubjectConfirmation holds the bearer confirmation.
type SubjectConfirmation struct {
	Method                string                `xml:"Method,attr"`
	SubjectConfirmationData SubjectConfirmationData `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
}

// SubjectConfirmationData holds timing and destination.
type SubjectConfirmationData struct {
	InResponseTo string `xml:"InResponseTo,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	Recipient    string `xml:"Recipient,attr"`
}

// Conditions specifies validity constraints.
type Conditions struct {
	NotBefore          string             `xml:"NotBefore,attr"`
	NotOnOrAfter       string             `xml:"NotOnOrAfter,attr"`
	AudienceRestriction AudienceRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
}

// AudienceRestriction limits the assertion audience.
type AudienceRestriction struct {
	Audience string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

// AuthnStatement records how the user was authenticated.
type AuthnStatement struct {
	AuthnInstant string       `xml:"AuthnInstant,attr"`
	SessionIndex string       `xml:"SessionIndex,attr"`
	AuthnContext AuthnContext `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext"`
}

// AuthnContext identifies the authentication method.
type AuthnContext struct {
	AuthnContextClassRef string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
}

// AttributeStatement holds user attributes.
type AttributeStatement struct {
	Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

// Attribute represents a single SAML attribute.
type Attribute struct {
	Name         string           `xml:"Name,attr"`
	NameFormat   string           `xml:"NameFormat,attr"`
	Values       []AttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

// AttributeValue holds the attribute value.
type AttributeValue struct {
	Type  string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Value string `xml:",chardata"`
}

// AssertionBuilder creates signed SAML assertions.
type AssertionBuilder struct {
	entityID string
	cert     *x509.Certificate
	key      *rsa.PrivateKey
}

// NewAssertionBuilder creates a new assertion builder.
func NewAssertionBuilder(entityID string, cert *x509.Certificate, key *rsa.PrivateKey) *AssertionBuilder {
	return &AssertionBuilder{
		entityID: entityID,
		cert:     cert,
		key:      key,
	}
}

// BuildResponse creates a complete SAML Response with a signed assertion.
func (b *AssertionBuilder) BuildResponse(
	authnReq *AuthnRequest,
	sess *session.Session,
	sp *config.TrustedSP,
) ([]byte, error) {
	now := time.Now().UTC()
	fiveMinLater := now.Add(5 * time.Minute)
	responseID := "_" + uuid.New().String()
	assertionID := "_" + uuid.New().String()
	timeFormat := "2006-01-02T15:04:05Z"

	// Build attributes from SP config
	var attrStmt *AttributeStatement
	if len(sp.Attributes) > 0 {
		attrs := make([]Attribute, 0, len(sp.Attributes))
		for _, spAttr := range sp.Attributes {
			val := resolveAttributeValue(spAttr.Source, sess)
			if val != "" {
				attrs = append(attrs, Attribute{
					Name:       spAttr.Name,
					NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
					Values: []AttributeValue{
						{Type: "xs:string", Value: val},
					},
				})
			}
		}
		// Add group attributes (multi-valued)
		for _, spAttr := range sp.Attributes {
			if spAttr.Source == "memberOf" && len(sess.Groups) > 0 {
				groupVals := make([]AttributeValue, 0, len(sess.Groups))
				for _, g := range sess.Groups {
					groupVals = append(groupVals, AttributeValue{Type: "xs:string", Value: g})
				}
				// Remove the single-value entry and replace with multi-value
				for i, a := range attrs {
					if a.Name == spAttr.Name {
						attrs[i].Values = groupVals
						break
					}
				}
			}
		}
		if len(attrs) > 0 {
			attrStmt = &AttributeStatement{Attributes: attrs}
		}
	}

	// Determine NameID value and format
	nameIDValue := sess.UPN
	if nameIDValue == "" {
		nameIDValue = sess.Username
	}
	nameIDFormat := "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	if authnReq.NameIDPolicy != nil && authnReq.NameIDPolicy.Format != "" {
		nameIDFormat = authnReq.NameIDPolicy.Format
	}

	// Determine ACS URL: prefer from request, fall back to SP config
	acsURL := authnReq.AssertionConsumerServiceURL
	if acsURL == "" {
		acsURL = sp.ACSURL
	}

	assertion := Assertion{
		ID:           assertionID,
		Version:      "2.0",
		IssueInstant: now.Format(timeFormat),
		AssIssuer:    RespIssuer{Value: b.entityID},
		Subject: Subject{
			NameID: NameID{
				Format: nameIDFormat,
				Value:  nameIDValue,
			},
			SubjectConfirmation: SubjectConfirmation{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: SubjectConfirmationData{
					InResponseTo: authnReq.ID,
					NotOnOrAfter: fiveMinLater.Format(timeFormat),
					Recipient:    acsURL,
				},
			},
		},
		Conditions: Conditions{
			NotBefore:    now.Format(timeFormat),
			NotOnOrAfter: fiveMinLater.Format(timeFormat),
			AudienceRestriction: AudienceRestriction{
				Audience: sp.EntityID,
			},
		},
		AuthnStmt: AuthnStatement{
			AuthnInstant: now.Format(timeFormat),
			SessionIndex: sess.ID,
			AuthnContext: AuthnContext{
				AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			},
		},
		AttrStmt: attrStmt,
	}

	// Sign the assertion
	signedAssertion, err := b.signAssertion(assertion, assertionID)
	if err != nil {
		return nil, fmt.Errorf("signing assertion: %w", err)
	}

	response := Response{
		XMLNS:        "urn:oasis:names:tc:SAML:2.0:assertion",
		ID:           responseID,
		Version:      "2.0",
		IssueInstant: now.Format(timeFormat),
		Destination:  acsURL,
		InResponseTo: authnReq.ID,
		RespIssuer:   RespIssuer{Value: b.entityID},
		Status: Status{
			StatusCode: StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"},
		},
		Assertion: signedAssertion,
	}

	output, err := xml.MarshalIndent(response, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling response: %w", err)
	}

	return output, nil
}

func (b *AssertionBuilder) signAssertion(assertion Assertion, assertionID string) (Assertion, error) {
	// Marshal assertion without signature for digest
	assertionXML, err := xml.Marshal(assertion)
	if err != nil {
		return assertion, fmt.Errorf("marshaling assertion for signing: %w", err)
	}

	// Compute SHA-256 digest
	digest := sha256.Sum256(assertionXML)
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	// Build SignedInfo
	signedInfo := SignedInfo{
		CanonicalizationMethod: CanonicalizationMethod{
			Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
		},
		SignatureMethod: SignatureMethod{
			Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		},
		Reference: Reference{
			URI: "#" + assertionID,
			Transforms: Transforms{
				Transform: []Transform{
					{Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature"},
					{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
				},
			},
			DigestMethod: DigestMethod{
				Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
			},
			DigestValue: digestB64,
		},
	}

	// Marshal SignedInfo for signing
	signedInfoXML, err := xml.Marshal(signedInfo)
	if err != nil {
		return assertion, fmt.Errorf("marshaling signed info: %w", err)
	}

	// Sign the SignedInfo
	siDigest := sha256.Sum256(signedInfoXML)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, b.key, crypto.SHA256, siDigest[:])
	if err != nil {
		return assertion, fmt.Errorf("RSA signing: %w", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)
	certB64 := base64.StdEncoding.EncodeToString(b.cert.Raw)

	assertion.Signature = &SignatureValue{
		SignedInfo:    signedInfo,
		SignatureVal:  sigB64,
		KeyInfoSig: KeyInfoSig{
			X509Data: X509DataSig{
				X509Certificate: certB64,
			},
		},
	}

	return assertion, nil
}

func resolveAttributeValue(source string, sess *session.Session) string {
	switch source {
	case "username":
		return sess.Username
	case "upn", "userPrincipalName":
		return sess.UPN
	case "email", "mail":
		return sess.Email
	case "displayName":
		return sess.DisplayName
	case "memberOf":
		// Multi-valued; handled separately
		if len(sess.Groups) > 0 {
			return sess.Groups[0]
		}
		return ""
	default:
		return ""
	}
}
