package xmldsig

import (
	"crypto"
	"testing"
	"time"
)

func TestNormalizeXMLDSigConfigDefaults(t *testing.T) {
	opts := normalizeXMLDSigConfig(XMLDSigConfig{})
	if opts.DataCanonicalizer == nil {
		t.Fatal("expected DataCanonicalizer to be set")
	}
	if opts.DataHash != crypto.SHA512 {
		t.Fatalf("expected DataHash to default to SHA512, got %v", opts.DataHash)
	}
	if opts.SignedInfoCanonicalizer == nil {
		t.Fatal("expected SignedInfoCanonicalizer to be set")
	}
	if opts.SignedInfoHash != crypto.SHA256 {
		t.Fatalf("expected SignedInfoHash to default to SHA256, got %v", opts.SignedInfoHash)
	}
	if opts.KeyInfoCanonicalizer == nil {
		t.Fatal("expected KeyInfoCanonicalizer to default to inclusive canonicalizer")
	}
	if opts.KeyInfoHash != crypto.SHA512 {
		t.Fatalf("expected KeyInfoHash to default to SHA512, got %v", opts.KeyInfoHash)
	}
}

func TestNormalizeXMLDSigConfigPreservesValues(t *testing.T) {
	custom := XMLDSigConfig{
		DataHash:                     crypto.SHA384,
		SignedInfoHash:               crypto.SHA224,
		IncludeKeyValue:              true,
		ReferenceKeyInfoInSignedInfo: true,
	}
	opts := normalizeXMLDSigConfig(custom)

	if opts.DataHash != crypto.SHA384 {
		t.Fatalf("expected DataHash to remain SHA384, got %v", opts.DataHash)
	}
	if opts.SignedInfoHash != crypto.SHA224 {
		t.Fatalf("expected SignedInfoHash to remain SHA224, got %v", opts.SignedInfoHash)
	}
	if !opts.IncludeKeyValue {
		t.Fatal("expected IncludeKeyValue to remain true")
	}
	if !opts.ReferenceKeyInfoInSignedInfo {
		t.Fatal("expected ReferenceKeyInfoInSignedInfo to remain true")
	}
}

func TestNormalizeXAdESConfigDefaults(t *testing.T) {
	opts := normalizeXAdESConfig(&XAdESConfig{})
	if opts == nil {
		t.Fatal("expected normalizeXAdESConfig to return non-nil options")
	}
	if opts.TimestampFormatter == nil {
		t.Fatal("expected TimestampFormatter to be set")
	}
	if got := opts.TimestampFormatter(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)); got != "2024-01-02T03:04:05+00:00" {
		t.Fatalf("unexpected timestamp format %q", got)
	}
	if opts.IssuerSerializer == nil {
		t.Fatal("expected IssuerSerializer to be set")
	}
	if opts.SigningCertificateHash != crypto.SHA512 {
		t.Fatalf("expected SigningCertificateHash to default to SHA512, got %v", opts.SigningCertificateHash)
	}
	if opts.SignedPropertiesCanonicalizer == nil {
		t.Fatal("expected SignedPropertiesCanonicalizer to be set")
	}
	if opts.SignedPropertiesHash != crypto.SHA512 {
		t.Fatalf("expected SignedPropertiesHash to default to SHA512, got %v", opts.SignedPropertiesHash)
	}
}

func TestNormalizeXAdESConfigValues(t *testing.T) {
	custom := &XAdESConfig{
		SigningCertificateHash: crypto.SHA1,
		SignedPropertiesHash:   crypto.SHA224,
	}
	opts := normalizeXAdESConfig(custom)

	if opts.SigningCertificateHash != crypto.SHA1 {
		t.Fatalf("expected SigningCertificateHash to remain SHA1, got %v", opts.SigningCertificateHash)
	}
	if opts.SignedPropertiesHash != crypto.SHA224 {
		t.Fatalf("expected SignedPropertiesHash to remain SHA224, got %v", opts.SignedPropertiesHash)
	}
}

func TestWithXMLDSigConfig(t *testing.T) {
	raw := XMLDSigConfig{IncludeKeyValue: true}
	opt := WithXMLDSigConfig(raw)
	o := &options{}
	if err := opt(o); err != nil {
		t.Fatalf("WithXMLDSigConfig returned error: %v", err)
	}
	if !o.xmldsigConfig.IncludeKeyValue {
		t.Fatal("expected IncludeKeyValue to be true")
	}
}

func TestWithXAdES(t *testing.T) {
	raw := XAdESConfig{
		Role: XAdESSignerRole("issuer"),
	}
	opt := WithXAdESConfig(raw)
	o := &options{}
	if err := opt(o); err != nil {
		t.Fatalf("WithXAdES returned error: %v", err)
	}
	if o.xadesConfig == nil {
		t.Fatal("expected xadesConfig to be set")
	}
	if o.xadesConfig.Role != "issuer" {
		t.Fatalf("expected Role to be cloned, got %+v", o.xadesConfig.Role)
	}
}
