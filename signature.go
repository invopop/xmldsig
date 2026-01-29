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

// Namespaces used in XML-DSig and XAdES.
const (
	NamespaceXAdES = "http://uri.etsi.org/01903/v1.3.2#"
	NamespaceDSig  = "http://www.w3.org/2000/09/xmldsig#"
)

// XML namespace prefixes.
const (
	XMLNS = "xmlns"
	XAdES = "xades"
	DSig  = "ds"
)

// Supported signing algorithms URIs.
const (
	AlgDSigRSASHA224     = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224"
	AlgDSigRSASHA256     = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	AlgDSigRSASHA384     = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	AlgDSigRSASHA512     = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	AlgDSigRSASHA512_224 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512/224"
	AlgDSigRSASHA512_256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512/256"
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

	X509Data *X509Data `xml:"ds:X509Data,omitempty"`
	KeyValue *KeyValue `xml:"ds:KeyValue,omitempty"` // optional, some APIs require it
}

// X509Data contains the certificate chain
type X509Data struct {
	X509Certificate []string `xml:"ds:X509Certificate"`
}

// KeyValue contains the RSA public key (optional, only specific APIs require it)
type KeyValue struct {
	Modulus  string `xml:"ds:RSAKeyValue>ds:Modulus"`
	Exponent string `xml:"ds:RSAKeyValue>ds:Exponent"`
}

// Object wraps the XAdES qualifying properties
type Object struct {
	QualifyingProperties *QualifyingProperties `xml:"xades:QualifyingProperties"`
}

// QualifyingProperties contains XAdES-specific signature data. XAdES-specific namespace is required, so we use `xades` prefix.
type QualifyingProperties struct {
	XAdESNamespace string `xml:"xmlns:xades,attr,omitempty"`
	ID             string `xml:"Id,attr"`
	Target         string `xml:"Target,attr"`

	SignedProperties   *EtreeElement       `xml:"xades:SignedProperties"` // etree, not struct - because it may contain custom elements from external configuration
	UnsignedProperties *UnsignedProperties `xml:"xades:UnsignedProperties,omitempty"`
}

const (
	signatureIDFormat               = "Signature-%s"
	signatureRootIDFormat           = "Signature-%s-Signature"
	sigPropertiesIDFormat           = "Signature-%s-SignedProperties"
	sigQualifyingPropertiesIDFormat = "Signature-%s-QualifyingProperties"
	signedDataReferenceID           = "Reference" // used by SignedPropertiesCustomElements configuration when wiring ObjectReference
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
		ID:            fmt.Sprintf(signatureRootIDFormat, o.docID),
		DSigNamespace: NamespaceDSig,
	}

	if o.xadesOptions.AttachQualifyingProperties {
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
		if !o.xadesOptions.AttachQualifyingProperties || s.Object == nil || s.Object.QualifyingProperties == nil {
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
		SignedProperties: NewEtreeElement(signedPropsElement),
	}

	s.Object = &Object{
		QualifyingProperties: qp,
	}
	return nil
}

func (s *Signature) buildSignedPropertiesElement() (*etree.Element, error) {
	cert := s.opts.cert
	if cert == nil {
		return nil, errors.New("missing certificate")
	}
	certHash := s.opts.xadesOptions.CertificateHash
	fingerprint, err := cert.Fingerprint(certHash)
	if err != nil {
		return nil, fmt.Errorf("certificate fingerprint: %w", err)
	}
	certDigestAlgorithm, err := hashAlgorithmURI(certHash)
	if err != nil {
		return nil, fmt.Errorf("certificate digest algorithm: %w", err)
	}

	el := etree.NewElement("xades:SignedProperties")
	el.CreateAttr("Id", fmt.Sprintf(sigPropertiesIDFormat, s.opts.docID))

	signedSignatureProps := el.CreateElement("xades:SignedSignatureProperties")
	signedSignatureProps.CreateElement("xades:SigningTime").SetText(s.opts.xadesOptions.TimestampFormatter(s.opts.timeNow()))

	signingCertificate := signedSignatureProps.CreateElement("xades:SigningCertificate")
	certElement := signingCertificate.CreateElement("xades:Cert")
	certDigest := certElement.CreateElement("xades:CertDigest")
	digestMethod := certDigest.CreateElement("ds:DigestMethod")
	digestMethod.CreateAttr("Algorithm", certDigestAlgorithm)
	certDigest.CreateElement("ds:DigestValue").SetText(fingerprint)

	issuerSerial := certElement.CreateElement("xades:IssuerSerial")
	issuerSerial.CreateElement("ds:X509IssuerName").SetText(s.serializeIssuer(cert))
	issuerSerial.CreateElement("ds:X509SerialNumber").SetText(cert.SerialNumber())

	appendCustomElements(el, s.opts.xadesOptions.SignedPropertiesCustomElements)
	appendCustomElements(signedSignatureProps, s.opts.xadesOptions.SignedSignaturePropertiesCustomElements)

	return el, nil
}

func (s *Signature) serializeIssuer(cert *Certificate) string {
	if serializer := s.opts.xadesOptions.IssuerSerializer; serializer != nil && cert.issuer != nil {
		return serializer(*cert.issuer)
	}
	return cert.Issuer()
}

func appendCustomElements(parent *etree.Element, elements *[]*etree.Element) {
	if parent == nil || elements == nil {
		return
	}
	for _, el := range *elements {
		if el == nil {
			continue
		}
		parent.AddChild(el.Copy())
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
	}

	if s.opts.xadesOptions.IncludeRSAKeyValue {
		privateKeyInfo := certificate.PrivateKeyInfo()
		if privateKeyInfo != nil {
			info.KeyValue = &KeyValue{
				Modulus:  privateKeyInfo.Modulus,
				Exponent: privateKeyInfo.Exponent,
			}
		}
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
		ID:   signedDataReferenceID,
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
	ns := s.opts.namespaces.Add(DSig, NamespaceDSig)

	// Add key info digest, if enabled
	keyInfoCanonicalizer := s.opts.xadesOptions.KeyInfoCanonicalizer
	keyInfoHash := s.opts.xadesOptions.KeyInfoHash
	if keyInfoHash != 0 && keyInfoCanonicalizer != nil {
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
	if s.opts.xadesOptions.AttachQualifyingProperties {
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
			URI: "#" + sp.ID(),
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
	ns := s.opts.namespaces.Add(DSig, s.DSigNamespace) // namespace of ds:Signature
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

// UnsignedProperties contains signature data not included in the SignedInfo (e.g. verified timestamp)
type UnsignedProperties struct {
	SignatureTimestamp *Timestamp `xml:"xades:UnsignedSignatureProperties>xades:SignatureTimestamp"`
}

func currentTime() time.Time {
	return time.Now().UTC()
}
