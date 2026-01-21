package xmldsig

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"sort"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// WithKSeF configures the signer to use defaults required by the Polish KSeF platform.
func WithKSeF() Option {
	return func(o *options) error {
		o.xades = nil
		o.xadesOptions = ksefXAdESOptions()
		return nil
	}
}

func ksefXAdESOptions() XAdESOptions {
	return XAdESOptions{
		DataCanonicalizer:                       dsig.MakeC14N10RecCanonicalizer(),
		DataHash:                                crypto.SHA256,
		TimestampFormatter:                      ksefTimestampFormatter,
		IssuerSerializer:                        ksefIssuerSerializer,
		SignedSignaturePropertiesCustomElements: nil,
		SignedPropertiesCustomElements:          nil,
		SignedPropertiesCanonicalizer:           dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
		CertificateHash:                         crypto.SHA256,
		SignedPropertiesHash:                    crypto.SHA256,
		KeyInfoHash:                             0,
		SignedInfoCanonicalizer:                 ksefSignedInfoCanonicalizer,
		SignedInfoHash:                          crypto.SHA256,
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

// TODO this should be done opposite way - SignedInfoCanonicalizer should be dsig.Canonicalizer
func ksefSignedInfoCanonicalizer(data []byte, ns Namespaces) ([]byte, error) {
	doc := etree.NewDocument()
	doc.Indent(etree.NoIndent)
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, err
	}

	root := doc.Root()
	for _, attr := range ns.defs() {
		match := false
		for _, existing := range root.Attr {
			if existing.Space == attr.Space && existing.Key == attr.Key {
				match = true
				break
			}
		}
		if !match {
			root.Attr = append(root.Attr, attr)
		}
	}
	sort.Sort(byCanonicalAttr(root.Attr))

	return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("").Canonicalize(root)
}
