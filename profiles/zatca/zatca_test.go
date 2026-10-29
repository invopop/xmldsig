package zatca

import (
	"strings"
	"testing"
	"time"
)

// TestZatcaTimestampFormatter checks that signing times are rendered in Saudi Arabia time without a zone suffix.
func TestZatcaTimestampFormatter(t *testing.T) {
	tests := []struct {
		name string
		in   time.Time
		want string
	}{
		{"utc", time.Date(2025, 7, 8, 9, 4, 41, 0, time.UTC), "2025-07-08T12:04:41"},
		{"utc crossing midnight", time.Date(2024, 12, 31, 22, 30, 0, 0, time.UTC), "2025-01-01T01:30:00"},
		{"non-utc", time.Date(2024, 1, 2, 3, 4, 5, 0, time.FixedZone("CET", 3600)), "2024-01-02T05:04:05"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := zatcaTimestampFormatter(tt.in); got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

// sampleSignedProperties is a compact <xades:SignedProperties> with three ds:*
// descendants (one of them empty) to exercise per-element namespace
// redeclaration and self-closing empty elements.
const sampleSignedProperties = `<xades:SignedProperties Id="xadesSignedProperties">` +
	`<xades:SignedSignatureProperties>` +
	`<xades:SigningTime>2024-01-01T03:00:00</xades:SigningTime>` +
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
