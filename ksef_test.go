package xmldsig

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestWithKSeFOptions(t *testing.T) {
	opt := WithKSeF()
	o := &options{}
	if err := opt(o); err != nil {
		t.Fatalf("WithKSeF returned error: %v", err)
	}

	opts := o.xadesOptions

	if opts.DataCanonicalizer == nil {
		t.Fatalf("expected DataCanonicalizer to be set")
	}
	if opts.DataCanonicalizer.Algorithm() != dsig.CanonicalXML10RecAlgorithmId {
		t.Fatalf("unexpected DataCanonicalizer algorithm: %s", opts.DataCanonicalizer.Algorithm())
	}
	if opts.DataHash != crypto.SHA512 {
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
	if opts.KeyInfoHash != 0 {
		t.Fatalf("expected KeyInfoHash to be zero, got %v", opts.KeyInfoHash)
	}
	if opts.KeyInfoCanonicalizer != nil {
		t.Fatal("expected KeyInfoCanonicalizer to be nil")
	}

	if opts.SignedInfoCanonicalizer == nil {
		t.Fatalf("expected SignedInfoCanonicalizer to be set")
	}
	if opts.SignedInfoCanonicalizer.Algorithm() != dsig.CanonicalXML10ExclusiveAlgorithmId {
		t.Fatalf("unexpected SignedInfoCanonicalizer algorithm: %s", opts.SignedInfoCanonicalizer.Algorithm())
	}
	if opts.SignedInfoHash != crypto.SHA256 {
		t.Fatalf("unexpected SignedInfoHash: %v", opts.SignedInfoHash)
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

func TestKsefIssuerSerializerMatchesCertificate(t *testing.T) {
	data, err := os.ReadFile("certs/cert-20260102-131809.pfx")
	if err != nil {
		t.Fatalf("failed to read certificate: %v", err)
	}

	_, certificate, _, err := pkcs12.DecodeChain(data, "")
	if err != nil {
		t.Fatalf("failed to decode certificate: %v", err)
	}

	var seq pkix.RDNSequence
	if _, err := asn1.Unmarshal(certificate.RawSubject, &seq); err != nil {
		t.Fatalf("failed to parse certificate subject: %v", err)
	}

	got := ksefIssuerSerializer(seq)
	want := "G=A, SN=R, SERIALNUMBER=TINPL-1192154885, CN=A R, C=PL"
	if got != want {
		t.Fatalf("unexpected issuer serialization from certificate:\nwant %q\n got %q", want, got)
	}
}
