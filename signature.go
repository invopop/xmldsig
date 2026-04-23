package xmldsig

import (
	"encoding/xml"
	"errors"
	"fmt"
	"time"

	"github.com/beevik/etree"
	"github.com/invopop/gobl/uuid"
)

// Namespaces used in XML-DSig and XAdES.
const (
	NamespaceXAdES  = "http://uri.etsi.org/01903/v1.3.2#"
	NamespaceDSig   = "http://www.w3.org/2000/09/xmldsig#"
	NamespaceDSig11 = "http://www.w3.org/2009/xmldsig11#"
)

// XML namespace prefixes.
const (
	XMLNS = "xmlns"
	XAdES = "xades"
	DSig  = "ds"
)

// Reference type URIs.
const (
	ReferenceTypeObject  = "http://www.w3.org/2000/09/xmldsig#Object"
	XpathFilterAlgorithm = "http://www.w3.org/TR/1999/REC-xpath-19991116"
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

	doc  []byte   `xml:"-"`
	opts *options `xml:"-"`
}

// AlgorithmMethod contains URL identifier of the signing algorithm (e.g. RSA-SHA256)
type AlgorithmMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
	XPath     string `xml:"ds:XPath,omitempty"`
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

// Reference contains information about the document part that is signed
// Note that there may be multiple references in a signature - in XAdES, one reference is for the outermost XML element,
// and another reference is for XAdES-specific data (xades:SignedProperties)
type Reference struct {
	ID   string `xml:"Id,attr,omitempty"`
	Type string `xml:"Type,attr,omitempty"`
	URI  string `xml:"URI,attr"`

	Transforms   *Transforms      `xml:"ds:Transforms,omitempty"`
	DigestMethod *AlgorithmMethod `xml:"ds:DigestMethod"`
	DigestValue  string           `xml:"ds:DigestValue"`
}

// Transforms contains a list of transforms to apply to the document before signing, as URL identifiers - usually includes canonicalization and hash algorithms.
type Transforms struct {
	Transform []*AlgorithmMethod `xml:"ds:Transform"`
}

// Value contains the signature itself (base64-encoded)
type Value struct {
	ID    string `xml:"Id,attr"`
	Value string `xml:",chardata"`
}

// KeyInfo contains the public key and certificate information
type KeyInfo struct {
	XMLName xml.Name `xml:"ds:KeyInfo"`
	ID      string   `xml:"Id,attr"`

	DSig11Namespace string `xml:"xmlns:dsig11,attr,omitempty"`

	X509Data *X509Data `xml:"ds:X509Data,omitempty"`
	KeyValue *KeyValue `xml:"ds:KeyValue,omitempty"` // optional, some APIs require it
}

// X509Data contains the certificate chain
type X509Data struct {
	X509Certificate []string `xml:"ds:X509Certificate"`
}

// KeyValue contains the public key (optional, only specific APIs require it)
type KeyValue struct {
	// RSA (XMLDSIG 1.0)
	RSA *RSAKeyValue `xml:"ds:RSAKeyValue,omitempty"`

	// EC (XMLDSIG 1.1)
	EC *ECKeyValue `xml:"dsig11:ECKeyValue,omitempty"`
}

type RSAKeyValue struct {
	XMLName xml.Name `xml:"ds:RSAKeyValue"`

	Modulus  string `xml:"ds:Modulus,omitempty"`
	Exponent string `xml:"ds:Exponent,omitempty"`
}

type ECKeyValue struct {
	XMLName xml.Name `xml:"dsig11:ECKeyValue"`

	NamedCurve NamedCurve `xml:"dsig11:NamedCurve"`
	PublicKey  string     `xml:"dsig11:PublicKey"`
}

type NamedCurve struct {
	URI string `xml:"URI,attr"`
}

const (
	signatureIDFormat               = "Signature-%s"
	signatureRootIDFormat           = "Signature-%s-Signature"
	sigPropertiesIDFormat           = "Signature-%s-SignedProperties"
	sigQualifyingPropertiesIDFormat = "Signature-%s-QualifyingProperties"
	signedDataReferenceID           = "Reference-%s"
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

	o.xmldsigConfig = normalizeXMLDSigConfig(o.xmldsigConfig)
	o.xadesConfig = normalizeXAdESConfig(o.xadesConfig)

	// Extract root namespaces
	if err := addRootNamespaces(o.namespaces, data); err != nil {
		return nil, fmt.Errorf("add root namespaces: %w", err)
	}

	s := &Signature{
		doc:           data,
		opts:          o,
		ID:            fmt.Sprintf(signatureRootIDFormat, o.docID),
		DSigNamespace: NamespaceDSig,
	}

	if o.xadesConfig != nil {
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
		if o.xadesConfig == nil || s.Object == nil || s.Object.QualifyingProperties == nil {
			return nil, errors.New("timestamp requires qualifying properties")
		}
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

// addRootNamespaces extracts namespaces from the root element - needed for inclusive canonicalization
func addRootNamespaces(ns Namespaces, data []byte) error {
	d := etree.NewDocument()
	if err := d.ReadFromBytes(data); err != nil {
		return fmt.Errorf("reading source data: %w", err)
	}

	for _, a := range d.Root().Attr {
		if a.Space == XMLNS {
			ns[a.Key] = a.Value
		} else if a.Space == "" && a.Key == XMLNS {
			ns[""] = a.Value
		}
	}
	return nil
}

// buildQualifyingProperties attaches XAdES policy configuration to the signature object.
// If not using XAdES, but raw XMLDSIG, this function should not be called.
func (s *Signature) buildQualifyingProperties() error {
	signedPropsElement, err := s.buildSignedPropertiesElement()
	if err != nil {
		return err
	}
	qp := &QualifyingProperties{
		XAdESNamespace:   NamespaceXAdES,
		ID:               fmt.Sprintf(sigQualifyingPropertiesIDFormat, s.opts.docID),
		Target:           fmt.Sprintf("#"+signatureRootIDFormat, s.opts.docID),
		SignedProperties: signedPropsElement,
	}

	s.Object = &Object{
		QualifyingProperties: qp,
	}
	return nil
}

// buildKeyInfo creates KeyInfo element, containing the certificate and public key
func (s *Signature) buildKeyInfo() {
	certificate := s.opts.cert
	info := &KeyInfo{
		ID: fmt.Sprintf(certificateIDFormat, s.opts.docID),
		X509Data: &X509Data{
			X509Certificate: []string{
				certificate.NakedPEM(),
			},
		},
	}

	if s.opts.xmldsigConfig.IncludeKeyValue {
		privateKeyInfo := certificate.PrivateKeyInfo()
		if privateKeyInfo != nil {
			if keyValue := buildKeyValue(privateKeyInfo); keyValue != nil {
				info.KeyValue = keyValue
				if privateKeyInfo.Algorithm == KeyAlgorithmECDSA {
					// ECDSA is only supported in XMLDSIG 1.1, so we need to add the dsig11 namespace
					info.DSig11Namespace = NamespaceDSig11
				}
			}
		}
	}

	for _, ca := range certificate.CaChain {
		info.X509Data.X509Certificate = append(info.X509Data.X509Certificate, NakedPEM(ca))
	}

	s.KeyInfo = info
}

// buildKeyValue creates KeyValue element, containing the public key
func buildKeyValue(info *PrivateKeyInfo) *KeyValue {
	switch info.Algorithm {
	case KeyAlgorithmRSA:
		if info.Modulus == "" || info.Exponent == "" {
			return nil
		}
		return &KeyValue{
			RSA: &RSAKeyValue{
				Modulus:  info.Modulus,
				Exponent: info.Exponent,
			},
		}
	case KeyAlgorithmECDSA:
		if info.CurveURI == "" || info.PublicKey == "" {
			return nil
		}
		return &KeyValue{
			EC: &ECKeyValue{
				NamedCurve: NamedCurve{URI: info.CurveURI},
				PublicKey:  info.PublicKey,
			},
		}
	default:
		return nil
	}
}

// buildSignedInfo creates SignedInfo element, containing the references to the signed data
// including their digest, and the canonicalization method and hash algorithm.
func (s *Signature) buildSignedInfo() error {
	signatureMethodAlgorithm, err := signatureMethodURI(s.opts.xmldsigConfig.SignedInfoHash, s.opts.cert.PublicKeyAlgorithm())
	if err != nil {
		return fmt.Errorf("signature method: %w", err)
	}
	signedInfoCanonicalizer := s.opts.xmldsigConfig.SignedInfoCanonicalizer

	si := &SignedInfo{
		CanonicalizationMethod: &AlgorithmMethod{
			Algorithm: signedInfoCanonicalizer.Algorithm().String(),
		},
		SignatureMethod: &AlgorithmMethod{
			Algorithm: signatureMethodAlgorithm,
		},
		Reference: []*Reference{},
	}

	var docToProcess = s.doc
	if s.opts.xmldsigConfig.PreHashTransforms != nil {
		transformed, err := s.opts.xmldsigConfig.PreHashTransforms(docToProcess)
		if err != nil {
			return fmt.Errorf("pre-hash transforms: %w", err)
		}
		docToProcess = transformed
	}

	// Add the document digest
	dataCanonicalizer := s.opts.xmldsigConfig.DataCanonicalizer
	dataHash := s.opts.xmldsigConfig.DataHash
	canonicalizedDoc, err := canonicalizeWith(docToProcess, s.opts.namespaces, dataCanonicalizer)
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

	var docRefType string
	if !s.opts.xmldsigConfig.OmitDocumentReferenceType {
		docRefType = ReferenceTypeObject
	}
	var docTransforms = s.opts.xmldsigConfig.DocumentTransforms
	if !s.opts.xmldsigConfig.OmitDataCanonicalizationTransform {
		if alg := dataCanonicalizer.Algorithm().String(); alg != "" {
			docTransforms = append(docTransforms, &AlgorithmMethod{Algorithm: alg})
		}
	}
	si.Reference = append(si.Reference, &Reference{
		ID:   fmt.Sprintf(signedDataReferenceID, s.opts.docID),
		Type: docRefType,
		URI:  "",
		Transforms: &Transforms{
			Transform: docTransforms,
		},
		DigestMethod: &AlgorithmMethod{
			Algorithm: docDigestAlgorithm,
		},
		DigestValue: docDigest,
	})
	ns := s.opts.namespaces.Add(DSig, NamespaceDSig)

	// Add key info digest, if enabled
	if s.opts.xmldsigConfig.ReferenceKeyInfoInSignedInfo {
		keyInfoCanonicalizer := s.opts.xmldsigConfig.KeyInfoCanonicalizer
		keyInfoHash := s.opts.xmldsigConfig.KeyInfoHash

		keyInfoBytes, err := xml.Marshal(s.KeyInfo)
		if err != nil {
			return fmt.Errorf("marshal key info: %w", err)
		}
		canonicalizedKeyInfo, err := canonicalizeWith(keyInfoBytes, ns, keyInfoCanonicalizer)
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

	// Finally, if enabled, add the XAdES digests
	if s.opts.xadesConfig != nil {
		sp := s.Object.QualifyingProperties.SignedProperties
		ns = ns.Add(XAdES, NamespaceXAdES)
		signedPropsCanonicalizer := s.opts.xadesConfig.SignedPropertiesCanonicalizer
		spBytes, err := xml.Marshal(sp)
		if err != nil {
			return fmt.Errorf("marshal signed properties: %w", err)
		}
		canonicalizedSignedProps, err := canonicalizeWith(spBytes, ns, signedPropsCanonicalizer)
		if err != nil {
			return fmt.Errorf("canonicalize signed properties: %w", err)
		}
		signedPropsHash := s.opts.xadesConfig.SignedPropertiesHash
		spDigest, err := digestBytes(canonicalizedSignedProps, signedPropsHash)
		if err != nil {
			return fmt.Errorf("xades digest: %w", err)
		}
		signedPropsAlgorithm, err := hashAlgorithmURI(signedPropsHash)
		if err != nil {
			return fmt.Errorf("xades digest algorithm: %w", err)
		}
		spRef := &Reference{
			URI:  "#" + sp.ID,
			Type: "http://uri.etsi.org/01903#SignedProperties",
			DigestMethod: &AlgorithmMethod{
				Algorithm: signedPropsAlgorithm,
			},
			DigestValue: spDigest,
		}
		if !s.opts.xadesConfig.OmitSignedPropertiesTransforms {
			spRef.Transforms = &Transforms{
				Transform: []*AlgorithmMethod{
					{Algorithm: signedPropsCanonicalizer.Algorithm().String()},
				},
			}
		}
		si.Reference = append(si.Reference, spRef)
	}

	s.SignedInfo = si
	return nil
}

// buildSignatureValue creates SignatureValue element, containing the
// signed hash of the SignedInfo element.
func (s *Signature) buildSignatureValue() error {
	// Take a copy of the signedInfo so that we can
	// modify the namespaces for canonicalization.
	data, err := xml.Marshal(s.SignedInfo)
	if err != nil {
		return err
	}
	ns := s.opts.namespaces.Add(DSig, s.DSigNamespace) // namespace of ds:Signature
	data, err = canonicalizeWith(data, ns, s.opts.xmldsigConfig.SignedInfoCanonicalizer)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}

	signatureValue, err := s.opts.cert.Sign(string(data[:]), s.opts.xmldsigConfig.SignedInfoHash, s.opts.xmldsigConfig.ECDSAFormat)
	if err != nil {
		return fmt.Errorf("sign SignedInfo: %w", err)
	}

	s.Value = &Value{
		ID:    fmt.Sprintf(signatureIDFormat+"-SignatureValue", s.opts.docID),
		Value: signatureValue,
	}
	return nil
}

// UnsignedProperties contains signature data not included in the SignedInfo (e.g. verified timestamp)
type UnsignedProperties struct {
	SignatureTimestamp *Timestamp `xml:"xades:UnsignedSignatureProperties>xades:SignatureTimestamp"`
}

func currentTime() time.Time {
	return time.Now().UTC()
}
