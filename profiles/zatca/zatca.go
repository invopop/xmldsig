package zatca

import (
	"crypto"
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
		ECDSAFormat:                       xmldsig.ECDSAFormatDER,
		OmitDocumentReferenceType:         true,
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
		TimestampFormatter:             zatcaTimestampFormatter,
		SigningCertificateHash:         crypto.SHA256,
		SignedPropertiesCanonicalizer:  dsig.MakeC14N11Canonicalizer(),
		SignedPropertiesHash:           crypto.SHA256,
		OmitSignedPropertiesTransforms: true,
		IncludeCaChain:                 true,
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

	// Insert dummy elements at positions matching the signed invoice layout.
	// InvoiceTBS removes them, and etree leaves residual newlines that match
	// ZATCA's XSLT-based element stripping.

	// 1. ext:UBLExtensions — first child element
	if invoice.SelectElement("UBLExtensions") == nil {
		if idx := indexOfFirstChildElement(invoice); idx >= 0 {
			invoice.InsertChildAt(idx, etree.NewElement("ext:UBLExtensions"))
			invoice.InsertChildAt(idx+1, &etree.CharData{Data: "\n  "})
		}
	}

	// 2. QR AdditionalDocumentReference — after the last existing ref
	if !hasQRRef(invoice) {
		if idx := indexOfLastChildElementByTag(invoice, "AdditionalDocumentReference"); idx >= 0 {
			qr := etree.NewElement("cac:AdditionalDocumentReference")
			qr.CreateElement("cbc:ID").SetText("QR")
			invoice.InsertChildAt(idx+1, &etree.CharData{Data: "\n  "})
			invoice.InsertChildAt(idx+2, qr)
		}
	}

	// 3. cac:Signature — before AccountingSupplierParty
	if invoice.SelectElement("Signature") == nil {
		if idx := indexOfChildElementByTag(invoice, "AccountingSupplierParty"); idx >= 0 {
			invoice.InsertChildAt(idx, etree.NewElement("cac:Signature"))
			invoice.InsertChildAt(idx+1, &etree.CharData{Data: "\n  "})
		}
	}

	data, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("write xml: %w", err)
	}

	return InvoiceTBS(data)
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

func InvoiceTBS(xmlData []byte) ([]byte, error) {
	doc := etree.NewDocument()
	doc.ReadSettings.PreserveCData = true
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return nil, err
	}

	invoice := doc.Root()
	if invoice == nil {
		return xmlData, nil
	}

	// ext:UBLExtensions — direct child of Invoice
	if el := invoice.SelectElement("UBLExtensions"); el != nil {
		invoice.RemoveChild(el)
	}

	// cac:AdditionalDocumentReference where cbc:ID = "QR" — direct child of Invoice
	for _, ref := range invoice.SelectElements("AdditionalDocumentReference") {
		if id := ref.SelectElement("ID"); id != nil && strings.TrimSpace(id.Text()) == "QR" {
			invoice.RemoveChild(ref)
			break
		}
	}

	// cac:Signature — direct child of Invoice
	if el := invoice.SelectElement("Signature"); el != nil {
		invoice.RemoveChild(el)
	}

	return doc.WriteToBytes()
}
