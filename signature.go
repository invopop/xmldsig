package xmldsig

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/invopop/gobl/uuid"
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
	AlgSHA512        = "http://www.w3.org/2001/04/xmlenc#sha512"
	AlgDSigSHA1      = "http://www.w3.org/2000/09/xmldsig#sha1"
	AlgDSigRSASHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	AlgDSigRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
)

// ISO8601 contains the time format used for signing times
// (based on https://en.wikipedia.org/wiki/ISO_8601)
const ISO8601 = "2006-01-02T15:04:05-07:00"

// Signature contains the complete signature to be added
// to the document.
type Signature struct {
	DSigNamespace string `xml:"xmlns:ds,attr,omitempty"`
	ID            string `xml:"Id,attr"`

	SignedInfo *SignedInfo `xml:"ds:SignedInfo"`
	Value      *Value      `xml:"ds:SignatureValue"`
	KeyInfo    *KeyInfo    `xml:"ds:KeyInfo"`
	Object     *Object     `xml:"ds:Object"`

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
	KeyValue *KeyValue `xml:"ds:KeyValue"`
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
	signerRole                      = "tercero" // "emisor"
)

func newSignature(data []byte, opts ...Option) (*Signature, error) {
	o := &options{
		docID:      uuid.NewV1().String(),
		namespaces: make(Namespaces),
	}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, fmt.Errorf("option: %w", err)
		}
	}
	if o.cert == nil {
		return nil, errors.New("cannot sign without a certificate")
	}
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

	if o.xaeds != "" {
		if err := s.buildQualifyingProperties(); err != nil {
			return nil, fmt.Errorf("qualifying properties: %w", err)
		}
	}

	if err := s.buildKeyInfo(); err != nil {
		return nil, fmt.Errorf("key info: %w", err)
	}

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
	qp := &QualifyingProperties{
		XAdESNamespace: NamespaceXAdES,
		ID:             fmt.Sprintf(sigQualifyingPropertiesIDFormat, s.opts.docID),
		Target:         fmt.Sprintf("#"+signatureRootIDFormat, s.opts.docID),
		SignedProperties: &SignedProperties{
			ID: fmt.Sprintf(sigPropertiesIDFormat, s.opts.docID),
			SignatureProperties: &SignedSignatureProperties{
				SigningTime: time.Now().UTC().Format(ISO8601),
				SigningCertificate: &SigningCertificate{
					CertDigest: &Digest{
						Method: &AlgorithmMethod{
							Algorithm: AlgSHA512,
						},
						Value: cert.Fingerprint(),
					},
					IssuerSerial: &IssuerSerial{
						IssuerName:   cert.Issuer(),
						SerialNumber: cert.SerialNumber(),
					},
				},
				PolicyIdentifier: policyIdentifier31(),
				SignerRole: &SignerRole{
					ClaimedRoles: &Roles{ClaimedRole: []string{s.opts.xaeds.String()}},
				},
			},
			DataObjectProperties: &DataObjectFormat{
				ObjectReference: "#" + s.referenceID,
				Description:     s.opts.xaedsDesc,
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
	s.Object = &Object{
		QualifyingProperties: qp,
	}
	return nil
}

func policyIdentifier31() *PolicyIdentifier {
	return &PolicyIdentifier{
		SigPolicyID: &SigPolicyID{
			Identifier:  "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf",
			Description: "Política de Firma FacturaE v3.1",
		},
		SigPolicyHash: &Digest{
			Method: &AlgorithmMethod{
				Algorithm: AlgDSigSHA1,
			},
			Value: "Ohixl6upD6av8N7pEvDABhEL6hM=",
		},
	}
}

func (s *Signature) buildKeyInfo() error {
	certificate := s.opts.cert
	info := &KeyInfo{
		ID: fmt.Sprintf(certificateIDFormat, s.opts.docID),
		X509Data: &X509Data{
			X509Certificate: []string{
				certificate.ToPEM(),
			},
		},
		KeyValue: &KeyValue{
			Modulus:  certificate.PrivateKeyInfo().Modulus,
			Exponent: certificate.PrivateKeyInfo().Exponent,
		},
	}

	for _, ca := range certificate.CaChain {
		info.X509Data.X509Certificate = append(info.X509Data.X509Certificate, ToPEM(ca))
	}

	s.KeyInfo = info

	return nil
}

// buildSignedInfo will add namespaces to the original properties
// as part of canonicalization, so we expect copies here.
func (s *Signature) buildSignedInfo() error {
	si := &SignedInfo{
		CanonicalizationMethod: &AlgorithmMethod{
			Algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
		},
		SignatureMethod: &AlgorithmMethod{
			Algorithm: AlgDSigRSASHA256,
			//Algorithm: AlgDSigRSASHA1,
		},
		Reference: []*Reference{},
	}

	// Add the document digest
	docDigest, err := digestBytes(s.doc, s.opts.namespaces)
	if err != nil {
		return fmt.Errorf("document digest: %w", err)
	}
	si.Reference = append(si.Reference, &Reference{
		ID:   s.referenceID,
		Type: "http://www.w3.org/2000/09/xmldsig#Object",
		URI:  "",
		Transforms: &Transforms{
			Transform: []*AlgorithmMethod{
				{Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature"},
			},
		},
		DigestMethod: &AlgorithmMethod{
			Algorithm: "http://www.w3.org/2001/04/xmlenc#sha512",
		},
		DigestValue: docDigest,
	})

	// Add the key info
	ns := s.opts.namespaces.Add(DSig, NamespaceDSig)
	keyInfoDigest, err := digest(s.KeyInfo, ns)
	if err != nil {
		return fmt.Errorf("key info digest: %w", err)
	}
	si.Reference = append(si.Reference, &Reference{
		URI: "#" + s.KeyInfo.ID,
		DigestMethod: &AlgorithmMethod{
			Algorithm: AlgSHA512,
		},
		DigestValue: keyInfoDigest,
	})

	// Finally, if present, add the XAdES digests
	if s.opts.xaeds != "" {
		sp := s.Object.QualifyingProperties.SignedProperties
		ns = ns.Add(XAdES, NamespaceXAdES)
		spDigest, err := digest(sp, ns)
		if err != nil {
			return fmt.Errorf("xades digest: %w", err)
		}
		si.Reference = append(si.Reference, &Reference{
			URI:  "#" + sp.ID,
			Type: "http://uri.etsi.org/01903#SignedProperties",
			DigestMethod: &AlgorithmMethod{
				Algorithm: AlgSHA512,
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
	// si.DSigNamespace = NamespaceDSig
	// si.FeNamespace = NamespaceFACTURAE_NAMESPACE

	data, err := xml.Marshal(s.SignedInfo)
	if err != nil {
		return err
	}
	ns := s.opts.namespaces.Add(DSig, s.DSigNamespace)
	data, err = canonicalize(data, ns)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}

	fmt.Printf("SIG INFO IS:\n`%s`\n\n", string(data))

	signatureValue, err := s.opts.cert.Sign(string(data[:]))
	if err != nil {
		return err
	}

	s.Value = &Value{
		ID:    fmt.Sprintf(signatureIDFormat+"-SignatureValue", s.opts.docID),
		Value: signatureValue,
	}
	return nil
}

func digest(doc interface{}, namespaces Namespaces) (string, error) {
	data, err := xml.Marshal(doc)
	if err != nil {
		return "", err
	}

	return digestBytes(data, namespaces)
}

// canonicalize will take the data and attempt to combine the namespaces provided.
// It doesn't do much more than that, as the golang xml lib already does most of the
// work of creating standard XML.
func canonicalize(data []byte, ns Namespaces) ([]byte, error) {
	d := etree.NewDocument()
	d.WriteSettings = etree.WriteSettings{
		CanonicalEndTags: true,
		CanonicalText:    true,
		CanonicalAttrVal: true,
	}
	d.Indent(etree.NoIndent)
	if err := d.ReadFromBytes(data); err != nil {
		return nil, err
	}

	r := d.Root()

	// Add any missing namespaces
	for _, v := range ns.defs() {
		match := false
		for _, a := range r.Attr {
			if a.Space == v.Space && a.Key == v.Key {
				match = true
			}
		}
		if !match {
			fmt.Printf("ADDING: %s\n", v.Key)
			r.Attr = append(r.Attr, v)
		}
	}
	sort.Sort(byCanonicalAttr(r.Attr))

	return d.WriteToBytes()
}

type byCanonicalAttr []etree.Attr

func (a byCanonicalAttr) Len() int {
	return len(a)
}

func (a byCanonicalAttr) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a byCanonicalAttr) Less(i, j int) bool {
	// we have two sets of attrs to sort, first those with the "xmlns" space,
	// then everything else.

	// First deal with default namespace which must always come first
	if a[i].Key == XMLNS {
		// Always first!
		return true
	}
	if a[j].Key == XMLNS {
		return false
	}

	// Next deal with the namespaces
	if a[i].Space == XMLNS && (a[j].Space != XMLNS) {
		return true
	}
	if a[j].Key == XMLNS || (a[i].Space != XMLNS && a[j].Space == XMLNS) {
		return false
	}

	// Spaces are ordered by their values, not names! (seriously WTF!)
	is := a[i].Space
	js := a[j].Space
	for _, v := range a {
		if v.Space == XMLNS {
			if v.Key == a[i].Space {
				is = v.Value
			}
			if v.Key == a[j].Space {
				js = v.Value
			}
		}
	}

	sp := strings.Compare(is, js)
	if sp == 0 {
		return strings.Compare(a[i].Key, a[j].Key) < 0
	}
	return sp < 0
}

func digestBytes(data []byte, ns Namespaces) (string, error) {
	out, err := canonicalize(data, ns)
	if err != nil {
		return "", err
	}
	fmt.Printf("DATA IS:\n`%s`\n\n", string(out))

	sum := sha512.Sum512(out)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

// UnsignedProperties contains ...
type UnsignedProperties struct {
	SignatureTimestamp *Timestamp `xml:"xades:UnsignedSignatureProperties>xades:SignatureTimestamp"`
}
