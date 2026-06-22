package zatca

import (
	"crypto"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/invopop/xmldsig"
	dsig "github.com/russellhaering/goxmldsig"
)

// XMLDSigConfig returns the ZATCA-specific XMLDSig configuration.
func XMLDSigConfig() xmldsig.XMLDSigConfig {
	return xmldsig.XMLDSigConfig{
		DataCanonicalizer:                 dsig.MakeC14N11Canonicalizer(),
		DataHash:                          crypto.SHA256,
		SignedInfoCanonicalizer:           dsig.MakeC14N11Canonicalizer(),
		SignedInfoHash:                    crypto.SHA256,
		ECDSAFormatDER:                    true,
		OmitDocumentReferenceType:         false,
		OmitDataCanonicalizationTransform: true,
		DocumentTransforms: []*xmldsig.AlgorithmMethod{
			{
				Algorithm: xmldsig.XpathFilterAlgorithm,
				XPath:     "not(//ancestor-or-self::ext:UBLExtensions)",
			},
			{
				Algorithm: xmldsig.XpathFilterAlgorithm,
				XPath:     "not(//ancestor-or-self::cac:Signature)",
			},
			{
				Algorithm: xmldsig.XpathFilterAlgorithm,
				XPath:     "not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])",
			},
			{
				Algorithm: dsig.CanonicalXML11AlgorithmId.String(),
			},
		},
		PreHashTransforms: zatcaPreHashTransforms,
	}
}

// XAdESConfig returns the ZATCA-specific XAdES configuration.
func XAdESConfig() xmldsig.XAdESConfig {
	return xmldsig.XAdESConfig{
		TimestampFormatter:            zatcaTimestampFormatter,
		IssuerSerializer:              zatcaIssuerSerializer,
		SigningCertificateHash:        crypto.SHA256,
		SignedPropertiesCanonicalizer: dsig.MakeC14N11Canonicalizer(),
		SignedPropertiesHash:          crypto.SHA256,
		IncludeCaChain:                false,
		HexEncodeDigests:              true,
		HashPEMText:                   true,
		SignedPropertiesSerializer:    serializeDom4jSignedProperties,
	}
}

func zatcaTimestampFormatter(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func zatcaPreHashTransforms(xmlData []byte) ([]byte, error) {
	doc := etree.NewDocument()
	doc.ReadSettings.PreserveCData = true
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return nil, fmt.Errorf("parse xml: %w", err)
	}

	invoice := doc.Root()
	if invoice == nil {
		return xmlData, nil
	}

	// Insert residual newlines that match ZATCA's XSLT-based element stripping.

	// 1. ext:UBLExtensions — first child element
	if invoice.SelectElement("UBLExtensions") == nil {
		if idx := indexOfFirstChildElement(invoice); idx >= 0 {
			invoice.InsertChildAt(idx, &etree.CharData{Data: "\n  "})
		}
	}

	// 2. QR AdditionalDocumentReference — after the last existing ref
	if !hasQRRef(invoice) {
		if idx := indexOfLastChildElementByTag(invoice, "AdditionalDocumentReference"); idx >= 0 {
			invoice.InsertChildAt(idx+1, &etree.CharData{Data: "\n  "})
		}
	}

	// 3. cac:Signature — before AccountingSupplierParty
	if invoice.SelectElement("Signature") == nil {
		if idx := indexOfChildElementByTag(invoice, "AccountingSupplierParty"); idx >= 0 {
			invoice.InsertChildAt(idx, &etree.CharData{Data: "\n  "})
		}
	}

	return doc.WriteToBytes()
}

func hasQRRef(invoice *etree.Element) bool {
	for _, ref := range invoice.SelectElements("AdditionalDocumentReference") {
		if id := ref.SelectElement("ID"); id != nil && strings.TrimSpace(id.Text()) == "QR" {
			return true
		}
	}
	return false
}

func indexOfFirstChildElement(el *etree.Element) int {
	for i, child := range el.Child {
		if _, ok := child.(*etree.Element); ok {
			return i
		}
	}
	return -1
}

func indexOfChildElementByTag(el *etree.Element, tag string) int {
	for i, child := range el.Child {
		if ce, ok := child.(*etree.Element); ok && ce.Tag == tag {
			return i
		}
	}
	return -1
}

func indexOfLastChildElementByTag(el *etree.Element, tag string) int {
	last := -1
	for i, child := range el.Child {
		if ce, ok := child.(*etree.Element); ok && ce.Tag == tag {
			last = i
		}
	}
	return last
}

// issuerAttrNames extends Go's stdlib pkix attribute-name table with
// DC (Domain Component), used by the ZATCA PCSID issuer.
var issuerAttrNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.5":                    "SERIALNUMBER",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "STREET",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.17":                   "POSTALCODE",
	"0.9.2342.19200300.100.1.25": "DC",
}

func zatcaIssuerSerializer(seq pkix.RDNSequence) string {
	parts := make([]string, 0, len(seq))
	for i := len(seq) - 1; i >= 0; i-- {
		rdn := seq[i]
		attrs := make([]string, 0, len(rdn))
		for _, atv := range rdn {
			name, ok := issuerAttrNames[atv.Type.String()]
			if !ok {
				name = atv.Type.String()
			}
			attrs = append(attrs, fmt.Sprintf("%s=%v", name, atv.Value))
		}
		parts = append(parts, strings.Join(attrs, "+"))
	}
	return strings.Join(parts, ", ")
}

// serializeDom4jSignedProperties produces a byte sequence equivalent to
// dom4j's asXML() output of an <xades:SignedProperties> element:
//   - xmlns:xades declared on the root element
//   - xmlns:ds declared on each ds:* descendant element individually
//   - self-closing for empty elements (etree default)
//   - original whitespace preserved
//
// It's the byte form ZATCA's fatoora validator digests. This lives in the
// ZATCA profile (rather than the core library) because it is a ZATCA-specific
// deviation, injected into signing via XAdESConfig.SignedPropertiesSerializer.
//
// Why this exists instead of standard canonicalization: ZATCA does NOT
// canonicalize SignedProperties before hashing it; it hashes dom4j's asXML()
// output directly. That output differs from C14N in three independent ways,
// none of which is a configurable option in a C14N canonicalizer:
//
//  1. Namespaces: dom4j redeclares xmlns:ds on every ds:* element, whereas
//     C14N declares it once on the nearest ancestor and lets it inherit.
//  2. Empty elements: dom4j keeps them self-closing (<ds:DigestMethod/>),
//     whereas canonical XML mandates expanded start+end tags
//     (<ds:DigestMethod></ds:DigestMethod>).
//  3. Root declarations: C14N hoists xmlns:ds onto the root and sorts the
//     namespace declarations; dom4j leaves only xmlns:xades there.
//
// Because no canonicalizer can reproduce these bytes, we must replicate dom4j's
// serialization here to match the digest the validator computes.
func serializeDom4jSignedProperties(spBytes []byte) ([]byte, error) {
	doc := etree.NewDocument()
	doc.ReadSettings.PreserveCData = true
	if err := doc.ReadFromBytes(spBytes); err != nil {
		return nil, fmt.Errorf("parse SignedProperties: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("SignedProperties has no root element")
	}
	out, err := serializeDom4jStyle(root)
	if err != nil {
		return nil, fmt.Errorf("dom4j serialize SignedProperties: %w", err)
	}
	return []byte(out), nil
}

func serializeDom4jStyle(sp *etree.Element) (string, error) {
	spCopy := sp.Copy()

	filtered := make([]etree.Attr, 0, len(spCopy.Attr))
	for _, a := range spCopy.Attr {
		if a.Space == xmldsig.XMLNS || (a.Space == "" && a.Key == xmldsig.XMLNS) {
			continue
		}
		filtered = append(filtered, a)
	}
	spCopy.Attr = filtered

	spCopy.Attr = append([]etree.Attr{{
		Space: xmldsig.XMLNS,
		Key:   xmldsig.XAdES,
		Value: xmldsig.NamespaceXAdES,
	}}, spCopy.Attr...)

	addDsNamespace(spCopy)

	d := etree.NewDocument()
	d.SetRoot(spCopy)
	out, err := d.WriteToBytes()
	if err != nil {
		return "", err
	}

	s := string(out)
	if strings.HasPrefix(s, "<?xml") {
		if idx := strings.Index(s, "?>"); idx >= 0 {
			s = s[idx+2:]
			if len(s) > 0 && s[0] == '\n' {
				s = s[1:]
			}
		}
	}

	return s, nil
}

func addDsNamespace(el *etree.Element) {
	for _, child := range el.ChildElements() {
		if child.Space == xmldsig.DSig {
			found := false
			for _, a := range child.Attr {
				if a.Space == xmldsig.XMLNS && a.Key == xmldsig.DSig {
					found = true
					break
				}
			}
			if !found {
				child.Attr = append([]etree.Attr{{
					Space: xmldsig.XMLNS,
					Key:   xmldsig.DSig,
					Value: xmldsig.NamespaceDSig,
				}}, child.Attr...)
			}
		}
		addDsNamespace(child)
	}
}
