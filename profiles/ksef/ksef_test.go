package ksef

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestKSeFTimestampFormatter(t *testing.T) {
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.FixedZone("CET", 3600))
	// ksefTimestampFormatter is internal, but we can test it because we are in package ksef
	if got := ksefTimestampFormatter(ts); got != "2024-01-02T02:04:05.0000000+00:00" {
		t.Fatalf("unexpected timestamp format: %s", got)
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
	// The path to certs might differ now that we are in a subdirectory.
	// But usually go test changes working directory to the package directory.
	// We need to verify where "certs/cert-20260102-131809.pfx" is relative to ksef package.
	// It is in ../certs/
	data, err := os.ReadFile("../../certs/cert-20260102-131809.pfx")
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
