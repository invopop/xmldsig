package zatca

import (
	"strings"
	"testing"
)

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
