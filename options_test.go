package xmldsig

import (
	"crypto"
	"testing"
	"time"
)

func TestNormalizeXAdESOptionsDefaults(t *testing.T) {
	opts := normalizeXAdESOptions(nil)
	if opts == nil {
		t.Fatal("expected normalizeXAdESOptions to return non-nil options")
	}

	if opts.DataHash != crypto.SHA512 {
		t.Fatalf("expected DataHash to default to SHA512, got %v", opts.DataHash)
	}
	if opts.TimestampFormatter == nil {
		t.Fatal("expected TimestampFormatter to be set")
	}
	if got := opts.TimestampFormatter(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)); got != "2024-01-02T03:04:05Z" {
		t.Fatalf("unexpected timestamp format %q", got)
	}
	if opts.IssuerSerializer == nil {
		t.Fatal("expected IssuerSerializer to be set")
	}
	if opts.CertificateHash != crypto.SHA512 {
		t.Fatalf("expected CertificateHash to default to SHA512, got %v", opts.CertificateHash)
	}
	if opts.SignedPropertiesHash != crypto.SHA512 {
		t.Fatalf("expected SignedPropertiesHash to default to SHA512, got %v", opts.SignedPropertiesHash)
	}
	if opts.SignedInfoCanonicalizer == nil {
		t.Fatal("expected SignedInfoCanonicalizer to be set")
	}
	if opts.SignedInfoHash != crypto.SHA256 {
		t.Fatalf("expected SignedInfoHash to default to SHA256, got %v", opts.SignedInfoHash)
	}
}

func TestNormalizeXAdESOptionsPreservesValues(t *testing.T) {
	custom := &XAdESOptions{
		DataHash:       crypto.SHA384,
		SignedInfoHash: crypto.SHA384,
	}

	opts := normalizeXAdESOptions(custom)

	if opts.DataHash != crypto.SHA384 {
		t.Fatalf("expected DataHash to remain SHA384, got %v", opts.DataHash)
	}
	if opts.SignedInfoHash != crypto.SHA384 {
		t.Fatalf("expected SignedInfoHash to remain SHA384, got %v", opts.SignedInfoHash)
	}
}

func TestWithRawOptions(t *testing.T) {
	raw := XAdESOptions{
		DataHash: crypto.SHA1,
	}
	opt := WithRawOptions(raw)
	o := &options{}
	if err := opt(o); err != nil {
		t.Fatalf("WithRawOptions returned error: %v", err)
	}
	if o.xadesOptions.DataHash != crypto.SHA1 {
		t.Fatalf("expected DataHash to be SHA1, got %v", o.xadesOptions.DataHash)
	}
}
