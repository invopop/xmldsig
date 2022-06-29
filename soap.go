package xmldsig

import (
	"encoding/xml"
	"errors"
	"fmt"
	"time"

	"github.com/invopop/gobl/uuid"
)

const SOAPNamespace = "http://schemas.xmlsoap.org/soap/envelope/"
const WSSENamespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
const WSUNamespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"

type Security struct {
	XMLName             xml.Name            `xml:"wsse:Security"`
	Namespace           string              `xml:"xmlns:wsse,attr,omitempty"`
	MustUnderstand      string              `xml:"soapenv:mustUnderstand,attr"`
	BinarySecurityToken BinarySecurityToken `xml:"wsse:BinarySecurityToken"`
	Signature           *Signature          `xml:"ds:Signature"`
	Timestamp           SOAPTimestamp       `xml:"wsu:Timestamp"`
}

type BinarySecurityToken struct {
	EncodingType string `xml:"EncodingType,attr"`
	ID           string `xml:"wsu:Id,attr,omitempty"`
	ValueType    string `xml:"ValueType,attr"`
	Value        string `xml:",chardata"`
}

type SecurityTokenReference struct {
	ID        string        `xml:"wsu:Id,attr,omitempty"`
	Reference WSSEReference `xml:"wsse:Reference"`
}

type WSSEReference struct {
	URI       string `xml:"URI,attr"`
	ValueType string `xml:"ValueType,attr"`
}

type SOAPTimestamp struct {
	ID      string `xml:"wsu:Id,attr,omitempty"`
	Created string `xml:"wsu:Created"`
	Expires string `xml:"wsu:Expires"`
}

func newSOAPSignature(body []byte, opts ...Option) (*Security, error) {
	o := &options{
		docID:      uuid.NewV1().String(), // Add default docID in case it has not been set as an option
		namespaces: make(Namespaces),
	}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, fmt.Errorf("invalid option: %w", err)
		}
	}

	o.namespaces.Add("ds", NamespaceDSig)
	o.namespaces.Add("wsse", WSSENamespace)
	o.namespaces.Add("wsu", WSUNamespace)
	o.namespaces.Add("soapenv", SOAPNamespace)

	if o.cert == nil {
		return nil, errors.New("cannot sign without a certificate")
	}

	timestamp := buildTimestamp(o.docID)

	signature, err := buildSignature(body, timestamp, o)
	if err != nil {
		return nil, err
	}

	return &Security{
		Namespace:           WSSENamespace,
		MustUnderstand:      "1",
		BinarySecurityToken: buildSecurityToken(o.cert, o.docID),
		Signature:           signature,
		Timestamp:           timestamp,
	}, nil
}

func buildSecurityToken(cert *Certificate, docID string) BinarySecurityToken {
	return BinarySecurityToken{
		EncodingType: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary",
		ID:           "CertId-" + docID,
		ValueType:    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
		Value:        cert.ToPEM(),
	}
}

func buildSignature(body []byte, timestamp SOAPTimestamp, options *options) (*Signature, error) {
	signedInfo, err := buildSignedInfo(body, timestamp, options.namespaces, options.docID)
	if err != nil {
		return nil, err
	}

	signatureValue, err := buildSignatureValue(signedInfo, options)
	if err != nil {
		return nil, err
	}

	return &Signature{
		DSigNamespace: NamespaceDSig,
		ID:            "SignatureID-" + options.docID,
		SignedInfo:    signedInfo,
		Value:         signatureValue,
		KeyInfo:       buildKeyInfo(options.docID),
		doc:           body,
		opts:          options,
		referenceID:   "ReferenceID-" + options.docID,
	}, nil
}

func buildSignedInfo(
	body []byte, timestamp SOAPTimestamp, namespaces Namespaces, docID string,
) (*SignedInfo, error) {
	bodyDigest, err := digestBytes(body, namespaces)
	if err != nil {
		return nil, err
	}

	timestampDigest, err := digest(timestamp, namespaces)
	if err != nil {
		return nil, err
	}

	return &SignedInfo{
		CanonicalizationMethod: &AlgorithmMethod{
			Algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
		},
		SignatureMethod: &AlgorithmMethod{
			Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
		},
		Reference: []*Reference{
			{
				URI: "#TimestampId-" + docID,
				DigestMethod: &AlgorithmMethod{
					Algorithm: "http://www.w3.org/2001/04/xmlenc#sha512",
				},
				DigestValue: timestampDigest,
			},
			{
				URI: "#BodyId-" + docID,
				DigestMethod: &AlgorithmMethod{
					Algorithm: "http://www.w3.org/2001/04/xmlenc#sha512",
				},
				DigestValue: bodyDigest,
			},
		},
	}, nil
}

func buildSignatureValue(signedInfo *SignedInfo, options *options) (*Value, error) {
	data, err := xml.Marshal(signedInfo)
	if err != nil {
		return nil, err
	}

	data, err = canonicalize(data, options.namespaces)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}

	signatureValue, err := options.cert.Sign(string(data[:]))
	if err != nil {
		return nil, err
	}

	return &Value{
		ID:    "SignatureValue-" + options.docID,
		Value: signatureValue,
	}, nil
}

func buildKeyInfo(docID string) *KeyInfo {
	return &KeyInfo{
		ID: "KeyId-" + docID,
		SecurityTokenReference: &SecurityTokenReference{
			ID: "SecTokId-" + docID,
			Reference: WSSEReference{
				URI:       "#CertId-" + docID,
				ValueType: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
			},
		},
	}
}

func buildTimestamp(docID string) SOAPTimestamp {
	return SOAPTimestamp{
		ID:      "TimestampId-" + docID,
		Created: time.Now().UTC().Format(ISO8601),
		Expires: time.Now().Add(60 * time.Second).UTC().Format(ISO8601),
	}
}
