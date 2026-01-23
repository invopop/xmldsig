package xmldsig

import (
	"encoding/xml"
	"errors"
	"fmt"
	"time"

	"github.com/beevik/etree"
	"github.com/invopop/gobl/uuid"
	dsig "github.com/russellhaering/goxmldsig"
)

// Namespaces
const (
	NamespaceXAdES = "http://uri.etsi.org/01903/v1.3.2#"
	NamespaceDSig  = "http://www.w3.org/2000/09/xmldsig#"
)

// Namespace names (short)
const (
	XMLNS = "xmlns"
	XAdES = "xades"
	DSig  = "ds"
)

// Algorithms
const (
	AlgDSigRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	AlgDSigRSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
)

// Signature contains the complete signature to be added
// to the document.
type Signature struct {
	DSigNamespace string   `xml:"xmlns:ds,attr,omitempty"`
	ID            string   `xml:"Id,attr"`
	XMLName       xml.Name `xml:"ds:Signature"`

	SignedInfo *SignedInfo `xml:"ds:SignedInfo"`
	Value      *Value      `xml:"ds:SignatureValue"`
	KeyInfo    *KeyInfo    `xml:"ds:KeyInfo"`
	Object     *Object     `xml:"ds:Object,omitempty"`

	doc         []byte   `xml:"-"`
	opts        *options `xml:"-"`
	referenceID string   `xml:"-"` // reference ID to main content
}

// SignedInfo contains the info that will be signed by
// the certificate.
type SignedInfo struct {
	XMLName xml.Name `xml:"ds:SignedInfo"`
	ID      string   `xml:"Id,attr,omitempty"`

	CanonicalizationMethod *AlgorithmMethod `xml:"ds:CanonicalizationMethod"`
	SignatureMethod        *AlgorithmMethod `xml:"ds:SignatureMethod"`
	Reference              []*Reference     `xml:"ds:Reference"`
}

// Reference contains ...
type Reference struct {
	ID   string `xml:"Id,attr,omitempty"`
	Type string `xml:"Type,attr,omitempty"`
	URI  string `xml:"URI,attr"`

	Transforms   *Transforms      `xml:"ds:Transforms,omitempty"`
	DigestMethod *AlgorithmMethod `xml:"ds:DigestMethod"`
	DigestValue  string           `xml:"ds:DigestValue"`
}

// Transforms contains ...
type Transforms struct {
	Transform []*AlgorithmMethod `xml:"ds:Transform"`
}

// Value contains ...
type Value struct {
	ID    string `xml:"Id,attr"`
	Value string `xml:",chardata"`
}

// KeyInfo contains ...
type KeyInfo struct {
	XMLName xml.Name `xml:"ds:KeyInfo"`
	ID      string   `xml:"Id,attr"`

	X509Data *X509Data `xml:"ds:X509Data,omitempty"`
	KeyValue *KeyValue `xml:"ds:KeyValue,omitempty"`
}

// X509Data contains ...
type X509Data struct {
	X509Certificate []string `xml:"ds:X509Certificate"`
}

// KeyValue contains ...
type KeyValue struct {
	Modulus  string `xml:"ds:RSAKeyValue>ds:Modulus"`
	Exponent string `xml:"ds:RSAKeyValue>ds:Exponent"`
}

// Object contains ...
type Object struct {
	QualifyingProperties *QualifyingProperties `xml:"xades:QualifyingProperties"`
}

// QualifyingProperties the funny XaDES signature confirmation policy data. This is the only place the
// `xades` namespace is required, so we can add it just here.
type QualifyingProperties struct {
	XAdESNamespace string `xml:"xmlns:xades,attr,omitempty"`
	ID             string `xml:"Id,attr"`
	Target         string `xml:"Target,attr"`

	SignedProperties   *SignedProperties   `xml:"xades:SignedProperties"`
	UnsignedProperties *UnsignedProperties `xml:"xades:UnsignedProperties,omitempty"`
}

// SignedProperties contains ...
type SignedProperties struct {
	XMLName xml.Name `xml:"xades:SignedProperties"`
	ID      string   `xml:"Id,attr"`

	SignatureProperties  *SignedSignatureProperties `xml:"xades:SignedSignatureProperties"`
	DataObjectProperties *DataObjectFormat          `xml:"xades:SignedDataObjectProperties>xades:DataObjectFormat"`
}

// SignedSignatureProperties contains ...
type SignedSignatureProperties struct {
	SigningTime        string              `xml:"xades:SigningTime"`
	SigningCertificate *SigningCertificate `xml:"xades:SigningCertificate"`
	PolicyIdentifier   *PolicyIdentifier   `xml:"xades:SignaturePolicyIdentifier"`
	SignerRole         *SignerRole         `xml:"xades:SignerRole"`
}

// SigningCertificate contains ...
type SigningCertificate struct {
	CertDigest   *Digest       `xml:"xades:Cert>xades:CertDigest"`
	IssuerSerial *IssuerSerial `xml:"xades:Cert>xades:IssuerSerial"`
}

// Digest contains ...
type Digest struct {
	Method *AlgorithmMethod `xml:"ds:DigestMethod"`
	Value  string           `xml:"ds:DigestValue"`
}

// AlgorithmMethod contains ...
type AlgorithmMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// IssuerSerial contains ...
type IssuerSerial struct {
	IssuerName   string `xml:"ds:X509IssuerName"`
	SerialNumber string `xml:"ds:X509SerialNumber"`
}

// PolicyIdentifier contains ...
type PolicyIdentifier struct {
	SigPolicyID   *SigPolicyID `xml:"xades:SignaturePolicyId>xades:SigPolicyId"`
	SigPolicyHash *Digest      `xml:"xades:SignaturePolicyId>xades:SigPolicyHash"`
}

// SigPolicyID contains ...
type SigPolicyID struct {
	Identifier  string `xml:"xades:Identifier"`
	Description string `xml:"xades:Description"`
}

// SignerRole contains ...
type SignerRole struct {
	ClaimedRoles *Roles `xml:"xades:ClaimedRoles"`
}

// Roles contains ...
type Roles struct {
	ClaimedRole []string `xml:"xades:ClaimedRole"`
}

// DataObjectFormat contains ...
type DataObjectFormat struct {
	ObjectReference string `xml:"ObjectReference,attr"`

	Description      string            `xml:"xades:Description"`
	ObjectIdentifier *ObjectIdentifier `xml:"xades:ObjectIdentifier"`
	MimeType         string            `xml:"xades:MimeType"`
	Encoding         string            `xml:"xades:Encoding"` // normally empty
}

// ObjectIdentifier holds and identifier
type ObjectIdentifier struct {
	Identifier  *Identifier `xml:"xades:Identifier"`
	Description string      `xml:"xades:Description"`
}

// Identifier contains ...
type Identifier struct {
	Qualifier string `xml:"Qualifier,attr"`
	Value     string `xml:",chardata"`
}

const (
	signatureIDFormat               = "Signature-%s"
	signatureRootIDFormat           = "Signature-%s-Signature"
	sigPropertiesIDFormat           = "Signature-%s-SignedProperties"
	sigQualifyingPropertiesIDFormat = "Signature-%s-QualifyingProperties"
	referenceIDFormat               = "Reference-%s"
	certificateIDFormat             = "Certificate-%s"
)

func newSignature(data []byte, opts ...Option) (*Signature, error) {
	o := &options{
		docID:      uuid.V1().String(),
		namespaces: make(Namespaces),
		timeNow:    currentTime,
	}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, fmt.Errorf("option: %w", err)
		}
	}
	if o.cert == nil {
		return nil, errors.New("cannot sign without a certificate")
	}

	o.xadesOptions = *normalizeXAdESOptions(&o.xadesOptions)

	// Extract root namespaces
	if err := addRootNamespaces(o.namespaces, data); err != nil {
		return nil, fmt.Errorf("add root namespaces: %w", err)
	}

	s := &Signature{
		doc:           data,
		opts:          o,
		referenceID:   fmt.Sprintf(referenceIDFormat, o.docID),
		ID:            fmt.Sprintf(signatureRootIDFormat, o.docID),
		DSigNamespace: NamespaceDSig,
	}

	if o.xades != nil {
		if err := s.buildQualifyingProperties(); err != nil {
			return nil, fmt.Errorf("qualifying properties: %w", err)
		}
	}

	s.buildKeyInfo()

	if err := s.buildSignedInfo(); err != nil {
		return nil, fmt.Errorf("signed info: %w", err)
	}

	if err := s.buildSignatureValue(); err != nil {
		return nil, fmt.Errorf("signature value: %w", err)
	}

	if o.timestampURL != "" {
		timestamp, timestampErr := buildTimestampValue(s.Value, o.timestampURL)
		if timestampErr != nil {
			return nil, timestampErr
		}
		s.Object.QualifyingProperties.UnsignedProperties = &UnsignedProperties{
			SignatureTimestamp: timestamp,
		}
	}

	return s, nil
}

func addRootNamespaces(ns Namespaces, data []byte) error {
	d := etree.NewDocument()
	if err := d.ReadFromBytes(data); err != nil {
		return fmt.Errorf("reading source data: %w", err)
	}

	for _, a := range d.Root().Attr {
		if a.Space == XMLNS {
			ns[a.Key] = a.Value
		}
	}
	return nil
}

// buildQualifyingProperties is used for the XAdES policy configuration.
func (s *Signature) buildQualifyingProperties() error {
	cert := s.opts.cert
	certHash := s.opts.xadesOptions.CertificateHash
	fingerprint, err := cert.Fingerprint(certHash)
	if err != nil {
		return fmt.Errorf("certificate fingerprint: %w", err)
	}
	certDigestAlgorithm, err := hashAlgorithmURI(certHash)
	if err != nil {
		return fmt.Errorf("certificate digest algorithm: %w", err)
	}

	qp := &QualifyingProperties{
		XAdESNamespace: NamespaceXAdES,
		ID:             fmt.Sprintf(sigQualifyingPropertiesIDFormat, s.opts.docID),
		Target:         fmt.Sprintf("#"+signatureRootIDFormat, s.opts.docID),
		SignedProperties: &SignedProperties{
			ID: fmt.Sprintf(sigPropertiesIDFormat, s.opts.docID),
			SignatureProperties: &SignedSignatureProperties{
				SigningTime: s.opts.xadesOptions.TimestampFormatter(s.opts.timeNow()),
				SigningCertificate: &SigningCertificate{
					CertDigest: &Digest{
						Method: &AlgorithmMethod{
							Algorithm: certDigestAlgorithm,
						},
						Value: fingerprint,
					},
					IssuerSerial: &IssuerSerial{
						IssuerName:   cert.Issuer(),
						SerialNumber: cert.SerialNumber(),
					},
				},
				PolicyIdentifier: s.xadesPolicyIdentifier(),
			},
			DataObjectProperties: &DataObjectFormat{
				ObjectReference: "#" + s.referenceID,
				Description:     s.opts.xades.Description,
				ObjectIdentifier: &ObjectIdentifier{
					Identifier: &Identifier{
						Qualifier: "OIDAsURN",
						Value:     "urn:oid:1.2.840.10003.5.109.10",
					},
					// Description: "",
				},
				MimeType: "text/xml",
			},
		},
	}

	if s.opts.xades.Role != "" {
		qp.SignedProperties.SignatureProperties.SignerRole = &SignerRole{
			ClaimedRoles: &Roles{ClaimedRole: []string{s.opts.xades.Role.String()}},
		}
	}

	s.Object = &Object{
		QualifyingProperties: qp,
	}
	return nil
}

func (s *Signature) xadesPolicyIdentifier() *PolicyIdentifier {
	policy := s.opts.xades.Policy
	if policy == nil {
		return nil
	}

	return &PolicyIdentifier{
		SigPolicyID: &SigPolicyID{
			Identifier:  policy.URL,
			Description: policy.Description,
		},
		SigPolicyHash: &Digest{
			Method: &AlgorithmMethod{
				Algorithm: policy.Algorithm,
			},
			Value: policy.Hash,
		},
	}
}

func (s *Signature) buildKeyInfo() {
	certificate := s.opts.cert
	info := &KeyInfo{
		ID: fmt.Sprintf(certificateIDFormat, s.opts.docID),
		X509Data: &X509Data{
			X509Certificate: []string{
				certificate.NakedPEM(),
			},
		},
		KeyValue: &KeyValue{
			Modulus:  certificate.PrivateKeyInfo().Modulus,
			Exponent: certificate.PrivateKeyInfo().Exponent,
		},
	}

	for _, ca := range certificate.CaChain {
		info.X509Data.X509Certificate = append(info.X509Data.X509Certificate, NakedPEM(ca))
	}

	s.KeyInfo = info
}

// buildSignedInfo will add namespaces to the original properties
// as part of canonicalization, so we expect copies here.
func (s *Signature) buildSignedInfo() error {
	signatureMethodAlgorithm, err := signatureMethodURI(s.opts.xadesOptions.SignedInfoHash)
	if err != nil {
		return fmt.Errorf("signature method: %w", err)
	}
	signedInfoCanonicalizer := s.opts.xadesOptions.SignedInfoCanonicalizer

	si := &SignedInfo{
		CanonicalizationMethod: &AlgorithmMethod{
			Algorithm: signedInfoCanonicalizer.Algorithm().String(),
		},
		SignatureMethod: &AlgorithmMethod{
			Algorithm: signatureMethodAlgorithm,
		},
		Reference: []*Reference{},
	}

	// Add the document digest
	// TODO this won't work if dataCanonicalizer is nil
	dataCanonicalizer := s.opts.xadesOptions.DataCanonicalizer
	dataHash := s.opts.xadesOptions.DataHash
	canonicalizedDoc, err := canonicalizeWith(s.doc, s.opts.namespaces, dataCanonicalizer)
	if err != nil {
		return fmt.Errorf("canonicalize document: %w", err)
	}
	docDigest, err := digestBytes(canonicalizedDoc, dataHash)
	if err != nil {
		return fmt.Errorf("document digest: %w", err)
	}
	docDigestAlgorithm, err := hashAlgorithmURI(dataHash)
	if err != nil {
		return fmt.Errorf("document digest algorithm: %w", err)
	}
	docTransforms := []*AlgorithmMethod{{Algorithm: dsig.EnvelopedSignatureAltorithmId.String()}}
	if alg := dataCanonicalizer.Algorithm().String(); alg != "" {
		docTransforms = append(docTransforms, &AlgorithmMethod{Algorithm: alg})
	}
	si.Reference = append(si.Reference, &Reference{
		ID:   s.referenceID,
		Type: "http://www.w3.org/2000/09/xmldsig#Object",
		URI:  "",
		Transforms: &Transforms{
			Transform: docTransforms,
		},
		DigestMethod: &AlgorithmMethod{
			Algorithm: docDigestAlgorithm,
		},
		DigestValue: docDigest,
	})

	// Add the key info
	ns := s.opts.namespaces.Add(DSig, NamespaceDSig)
	if s.opts.xadesOptions.KeyInfoHash != 0 {
		keyInfoHash := s.opts.xadesOptions.KeyInfoHash
		keyInfoBytes, err := xml.Marshal(s.KeyInfo)
		if err != nil {
			return fmt.Errorf("marshal key info: %w", err)
		}
		canonicalizedKeyInfo, err := canonicalizeWith(keyInfoBytes, ns, dsig.MakeC14N10RecCanonicalizer())
		if err != nil {
			return fmt.Errorf("canonicalize key info: %w", err)
		}
		keyInfoDigest, err := digestBytes(canonicalizedKeyInfo, keyInfoHash)
		if err != nil {
			return fmt.Errorf("key info digest: %w", err)
		}
		keyInfoAlgorithm, err := hashAlgorithmURI(keyInfoHash)
		if err != nil {
			return fmt.Errorf("key info digest algorithm: %w", err)
		}
		si.Reference = append(si.Reference, &Reference{
			URI: "#" + s.KeyInfo.ID,
			DigestMethod: &AlgorithmMethod{
				Algorithm: keyInfoAlgorithm,
			},
			DigestValue: keyInfoDigest,
		})
	}

	// Finally, if present, add the XAdES digests
	if s.opts.xades != nil {
		sp := s.Object.QualifyingProperties.SignedProperties
		ns = ns.Add(XAdES, NamespaceXAdES)
		signedPropsCanonicalizer := s.opts.xadesOptions.SignedPropertiesCanonicalizer
		spBytes, err := xml.Marshal(sp)
		if err != nil {
			return fmt.Errorf("marshal signed properties: %w", err)
		}
		canonicalizedSignedProps, err := canonicalizeWith(spBytes, ns, signedPropsCanonicalizer)
		if err != nil {
			return fmt.Errorf("canonicalize signed properties: %w", err)
		}
		signedPropsHash := s.opts.xadesOptions.SignedPropertiesHash
		spDigest, err := digestBytes(canonicalizedSignedProps, signedPropsHash)
		if err != nil {
			return fmt.Errorf("xades digest: %w", err)
		}
		signedPropsAlgorithm, err := hashAlgorithmURI(signedPropsHash)
		if err != nil {
			return fmt.Errorf("xades digest algorithm: %w", err)
		}
		si.Reference = append(si.Reference, &Reference{
			URI: "#" + sp.ID,
			Transforms: &Transforms{
				Transform: []*AlgorithmMethod{
					{Algorithm: signedPropsCanonicalizer.Algorithm().String()},
				},
			},
			Type: "http://uri.etsi.org/01903#SignedProperties",
			DigestMethod: &AlgorithmMethod{
				Algorithm: signedPropsAlgorithm,
			},
			DigestValue: spDigest,
		})
	}

	s.SignedInfo = si
	return nil
}

// newSignatureValue takes a copy of the signedInfo so that we can
// modify the namespaces for canonicalization.
func (s *Signature) buildSignatureValue() error {
	data, err := xml.Marshal(s.SignedInfo)
	if err != nil {
		return err
	}
	ns := s.opts.namespaces.Add(DSig, s.DSigNamespace)
	data, err = canonicalizeWith(data, ns, s.opts.xadesOptions.SignedInfoCanonicalizer)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}

	signatureValue, err := s.opts.cert.Sign(string(data[:]), s.opts.xadesOptions.SignedInfoHash)
	if err != nil {
		return fmt.Errorf("sign SignedInfo: %w", err)
	}

	s.Value = &Value{
		ID:    fmt.Sprintf(signatureIDFormat+"-SignatureValue", s.opts.docID),
		Value: signatureValue,
	}
	return nil
}

// UnsignedProperties contains ...
type UnsignedProperties struct {
	SignatureTimestamp *Timestamp `xml:"xades:UnsignedSignatureProperties>xades:SignatureTimestamp"`
}

func currentTime() time.Time {
	return time.Now().UTC()
}
