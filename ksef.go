package xmldsig

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

// WithKSeF configures the signer to use defaults required by the Polish KSeF platform.
func WithKSeF() Option {
	return func(o *options) error {
		o.xadesOptions = ksefXAdESOptions()
		return nil
	}
}

func ksefXAdESOptions() XAdESOptions {
	// List of allowed canonicalizers: https://github.com/CIRFMF/ksef-docs/blob/main/auth/podpis-xades.md
	return XAdESOptions{
		DataCanonicalizer:                       dsig.MakeC14N10RecCanonicalizer(), // exclusive canonicalizer works too, even though xmlns:xsi and xmlns:xsd attributes are removed from the outermost XML element
		DataHash:                                crypto.SHA512,                     // SHA-256 works too
		TimestampFormatter:                      ksefTimestampFormatter,
		IssuerSerializer:                        ksefIssuerSerializer,
		AttachQualifyingProperties:              true,
		SignedSignaturePropertiesCustomElements: nil,
		SignedPropertiesCustomElements:          nil,
		SignedPropertiesCanonicalizer:           dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
		CertificateHash:                         crypto.SHA512, // SHA-256 works too
		SignedPropertiesHash:                    crypto.SHA512, // SHA-256 works too
		KeyInfoHash:                             0,
		SignedInfoCanonicalizer:                 dsig.MakeC14N10RecCanonicalizer(),
		SignedInfoHash:                          crypto.SHA256, // used together with RSA algorithm to sign the SignedInfo element
		IncludeRSAKeyValue:                      false,
	}
}

func ksefTimestampFormatter(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.0000000-07:00")
}

var (
	oidGivenName = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidSurname   = asn1.ObjectIdentifier{2, 5, 4, 4}
)

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func attributeValue(name pkix.Name, oid asn1.ObjectIdentifier) string {
	for _, atv := range name.Names {
		if atv.Type.Equal(oid) {
			if str, ok := atv.Value.(string); ok {
				return str
			}
			return fmt.Sprint(atv.Value)
		}
	}
	for _, atv := range name.ExtraNames {
		if atv.Type.Equal(oid) {
			if str, ok := atv.Value.(string); ok {
				return str
			}
			return fmt.Sprint(atv.Value)
		}
	}
	return ""
}

func ksefIssuerSerializer(seq pkix.RDNSequence) string {
	var name pkix.Name
	name.FillFromRDNSequence(&seq)

	given := attributeValue(name, oidGivenName)
	surname := attributeValue(name, oidSurname)
	return fmt.Sprintf(
		"G=%s, SN=%s, SERIALNUMBER=%s, CN=%s, C=%s",
		given,
		surname,
		name.SerialNumber,
		name.CommonName,
		firstOrEmpty(name.Country),
	)
}
