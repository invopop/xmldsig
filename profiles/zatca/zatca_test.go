package zatca

import (
	"strings"
	"testing"
	"time"
)

func TestZatcaTimestampFormatter(t *testing.T) {
	// A non-UTC input must be normalized to UTC and rendered with a trailing Z.
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.FixedZone("CET", 3600))
	if got := zatcaTimestampFormatter(ts); got != "2024-01-02T02:04:05Z" {
		t.Fatalf("unexpected timestamp format: %s", got)
	}
}

// invoiceMissingStripped is a minimal, single-line UBL invoice that lacks the
// three elements ZATCA's XSLT strips (UBLExtensions, the QR
// AdditionalDocumentReference, and cac:Signature). Keeping it on one line means
// every newline in the transformed output was inserted by the transform.
const invoiceMissingStripped = `<Invoice xmlns:cac="urn:cac" xmlns:cbc="urn:cbc" xmlns:ext="urn:ext">` +
	`<cbc:ID>1</cbc:ID>` +
	`<cac:AdditionalDocumentReference><cbc:ID>ICV</cbc:ID></cac:AdditionalDocumentReference>` +
	`<cac:AccountingSupplierParty><cac:Party/></cac:AccountingSupplierParty>` +
	`</Invoice>`

// invoiceWithStripped already contains all three elements, so the transform
// must not insert any residual newlines.
const invoiceWithStripped = `<Invoice xmlns:cac="urn:cac" xmlns:cbc="urn:cbc" xmlns:ext="urn:ext">` +
	`<ext:UBLExtensions><ext:UBLExtension/></ext:UBLExtensions>` +
	`<cbc:ID>1</cbc:ID>` +
	`<cac:AdditionalDocumentReference><cbc:ID>QR</cbc:ID></cac:AdditionalDocumentReference>` +
	`<cac:Signature><cbc:ID>sig</cbc:ID></cac:Signature>` +
	`<cac:AccountingSupplierParty><cac:Party/></cac:AccountingSupplierParty>` +
	`</Invoice>`

func TestZatcaPreHashTransformsInsertsNewlines(t *testing.T) {
	out, err := zatcaPreHashTransforms([]byte(invoiceMissingStripped))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// One newline per stripped element: UBLExtensions, QR ref, Signature.
	if got := strings.Count(string(out), "\n"); got != 3 {
		t.Fatalf("expected 3 inserted newlines, got %d:\n%s", got, out)
	}

	// The UBLExtensions placeholder lands before the first child element.
	if !strings.Contains(string(out), "\n  <cbc:ID>1</cbc:ID>") {
		t.Fatalf("missing newline before first child element:\n%s", out)
	}
	// The Signature placeholder lands immediately before AccountingSupplierParty.
	if !strings.Contains(string(out), "\n  <cac:AccountingSupplierParty>") {
		t.Fatalf("missing newline before AccountingSupplierParty:\n%s", out)
	}
}

func TestZatcaPreHashTransformsSkipsExistingElements(t *testing.T) {
	out, err := zatcaPreHashTransforms([]byte(invoiceWithStripped))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All three elements are present, so nothing should be inserted.
	if got := strings.Count(string(out), "\n"); got != 0 {
		t.Fatalf("expected no inserted newlines, got %d:\n%s", got, out)
	}
}

func TestZatcaPreHashTransformsInvalidXML(t *testing.T) {
	if _, err := zatcaPreHashTransforms([]byte("<Invoice><unclosed>")); err == nil {
		t.Fatal("expected error for malformed xml")
	}
}

// sampleSignedProperties is a compact <xades:SignedProperties> with three ds:*
// descendants (one of them empty) to exercise per-element namespace
// redeclaration and self-closing empty elements.
const sampleSignedProperties = `<xades:SignedProperties Id="xadesSignedProperties">` +
	`<xades:SignedSignatureProperties>` +
	`<xades:SigningTime>2024-01-01T00:00:00Z</xades:SigningTime>` +
	`<xades:Cert><xades:CertDigest>` +
	`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>` +
	`<ds:DigestValue>ABC123</ds:DigestValue>` +
	`<ds:Empty></ds:Empty>` +
	`</xades:CertDigest></xades:Cert>` +
	`</xades:SignedSignatureProperties>` +
	`</xades:SignedProperties>`

func TestSerializeDom4jSignedProperties(t *testing.T) {
	out, err := serializeDom4jSignedProperties([]byte(sampleSignedProperties))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := string(out)

	const dsNS = `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`

	// xmlns:xades is declared on the root, xmlns:ds is NOT hoisted there.
	if !strings.HasPrefix(got, `<xades:SignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="xadesSignedProperties">`) {
		t.Fatalf("unexpected root element:\n%s", got)
	}
	if strings.Contains(got, `<xades:SignedProperties xmlns:ds=`) {
		t.Fatalf("xmlns:ds should not be hoisted onto the root:\n%s", got)
	}

	// xmlns:ds is redeclared on each of the three ds:* descendants.
	if n := strings.Count(got, dsNS); n != 3 {
		t.Fatalf("expected xmlns:ds redeclared on 3 ds:* elements, got %d:\n%s", n, got)
	}

	// Empty elements stay self-closing (dom4j default), not expanded.
	if !strings.Contains(got, `<ds:DigestMethod `+dsNS+` Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`) {
		t.Fatalf("expected self-closing ds:DigestMethod:\n%s", got)
	}
	if !strings.Contains(got, `<ds:Empty `+dsNS+`/>`) {
		t.Fatalf("expected self-closing ds:Empty:\n%s", got)
	}
}

func TestSerializeDom4jSignedPropertiesInvalidXML(t *testing.T) {
	if _, err := serializeDom4jSignedProperties([]byte("<xades:SignedProperties>")); err == nil {
		t.Fatal("expected error for malformed xml")
	}
}
