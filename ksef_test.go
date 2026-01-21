package xmldsig

import (
	"crypto"
	"crypto/x509/pkix"
	"reflect"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

func TestWithKSeFOptions(t *testing.T) {
	opt := WithKSeF()
	o := &options{}
	if err := opt(o); err != nil {
		t.Fatalf("WithKSeF returned error: %v", err)
	}

	if o.xades != nil {
		t.Fatalf("expected xades config to be nil for KSeF, got %#v", o.xades)
	}

	opts := o.xadesOptions

	if opts.DataCanonicalizer == nil {
		t.Fatalf("expected DataCanonicalizer to be set")
	}
	if opts.DataCanonicalizer.Algorithm() != dsig.CanonicalXML10RecAlgorithmId {
		t.Fatalf("unexpected DataCanonicalizer algorithm: %s", opts.DataCanonicalizer.Algorithm())
	}
	if opts.DataHash != crypto.SHA256 {
		t.Fatalf("unexpected DataHash: %v", opts.DataHash)
	}

	if opts.TimestampFormatter == nil {
		t.Fatalf("expected TimestampFormatter to be set")
	}
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.FixedZone("CET", 3600))
	if got := opts.TimestampFormatter(ts); got != "2024-01-02T02:04:05.0000000+00:00" {
		t.Fatalf("unexpected timestamp format: %s", got)
	}

	if opts.IssuerSerializer == nil {
		t.Fatalf("expected IssuerSerializer to be set")
	}

	if opts.SignedSignaturePropertiesCustomElements != nil {
		t.Fatalf("expected SignedSignaturePropertiesCustomElements to be nil")
	}
	if opts.SignedPropertiesCustomElements != nil {
		t.Fatalf("expected SignedPropertiesCustomElements to be nil")
	}

	if opts.SignedPropertiesCanonicalizer == nil {
		t.Fatalf("expected SignedPropertiesCanonicalizer to be set")
	}
	if opts.SignedPropertiesCanonicalizer.Algorithm() != dsig.CanonicalXML10ExclusiveAlgorithmId {
		t.Fatalf("unexpected SignedPropertiesCanonicalizer algorithm: %s", opts.SignedPropertiesCanonicalizer.Algorithm())
	}

	if opts.CertificateHash != crypto.SHA512 {
		t.Fatalf("unexpected CertificateHash: %v", opts.CertificateHash)
	}
	if opts.SignedPropertiesHash != crypto.SHA512 {
		t.Fatalf("unexpected SignedPropertiesHash: %v", opts.SignedPropertiesHash)
	}
	if opts.KeyInfoHash != crypto.SHA512 {
		t.Fatalf("unexpected KeyInfoHash: %v", opts.KeyInfoHash)
	}

	if opts.SignedInfoCanonicalizer == nil {
		t.Fatalf("expected SignedInfoCanonicalizer to be set")
	}
	if reflect.ValueOf(opts.SignedInfoCanonicalizer).Pointer() != reflect.ValueOf(ksefSignedInfoCanonicalizer).Pointer() {
		t.Fatalf("unexpected SignedInfoCanonicalizer function assigned")
	}
	data := []byte(`<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="test"/></ds:SignedInfo>`)
	if _, err := opts.SignedInfoCanonicalizer(data, Namespaces{DSig: NamespaceDSig}); err != nil {
		t.Fatalf("SignedInfoCanonicalizer returned error: %v", err)
	}
	if opts.SignedInfoHash != crypto.SHA256 {
		t.Fatalf("unexpected SignedInfoHash: %v", opts.SignedInfoHash)
	}
	if opts.SignedInfoSignatureAlgorithm != SignedInfoSignatureAlgorithmRSA {
		t.Fatalf("unexpected SignedInfoSignatureAlgorithm: %s", opts.SignedInfoSignatureAlgorithm)
	}
}

func TestKsefIssuerSerializerFormatsAttributes(t *testing.T) {
	name := pkix.Name{
		SerialNumber: "123456789",
		CommonName:   "Example Cert",
		Country:      []string{"PL"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: oidGivenName, Value: "Jan"},
			{Type: oidSurname, Value: "Kowalski"},
		},
	}

	seq := name.ToRDNSequence()

	got := ksefIssuerSerializer(seq)
	want := "G=Jan, SN=Kowalski, SERIALNUMBER=123456789, CN=Example Cert, C=PL"
	if got != want {
		t.Fatalf("unexpected issuer serialization:\nwant %q\n got %q", want, got)
	}
}

func TestKsefIssuerSerializerHandlesMissingValues(t *testing.T) {
	var name pkix.Name
	seq := name.ToRDNSequence()

	got := ksefIssuerSerializer(seq)
	want := "G=, SN=, SERIALNUMBER=, CN=, C="
	if got != want {
		t.Fatalf("unexpected issuer serialization for empty name:\nwant %q\n got %q", want, got)
	}
}
