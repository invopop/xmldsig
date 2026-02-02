package xmldsig

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"
)

// KSeFXAdESOptions returns the KSeF-specific XAdES configuration.
func KSeFXAdESOptions() XAdESOptions {
	// List of allowed canonicalizers: https://github.com/CIRFMF/ksef-docs/blob/main/auth/podpis-xades.md
	return XAdESOptions{
		TimestampFormatter: ksefTimestampFormatter,
		IssuerSerializer:   ksefIssuerSerializer,
	}
}

func ksefTimestampFormatter(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.0000000+00:00")
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
