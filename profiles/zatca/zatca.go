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
