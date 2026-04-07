package facturae

import (
	"crypto/x509/pkix"
	"time"

	"github.com/invopop/xmldsig"
	dsig "github.com/russellhaering/goxmldsig"
)

// XMLDSigConfig returns the XMLDSig defaults required by the FacturaE profile.
func XMLDSigConfig() xmldsig.XMLDSigConfig {
	return xmldsig.XMLDSigConfig{
		IncludeKeyValue:              true,
		ReferenceKeyInfoInSignedInfo: true,
	}
}

// XAdESConfig builds the FacturaE-specific XAdES configuration from the provided config.
func XAdESConfig(opts xmldsig.XAdESConfig) xmldsig.XAdESConfig {
	opts.TimestampFormatter = facturaeTimestampFormatter
	opts.IssuerSerializer = facturaeIssuerSerializer
	opts.SignedPropertiesCanonicalizer = dsig.MakeC14N10RecCanonicalizer()

	if opts.DataObjectFormat == nil {
		opts.DataObjectFormat = &xmldsig.DataObjectFormat{}
	}
	opts.DataObjectFormat.Description = opts.Description
	opts.DataObjectFormat.MimeType = "text/xml"
	opts.DataObjectFormat.ObjectIdentifier = &xmldsig.ObjectIdentifier{
		Identifier: xmldsig.Identifier{
			Qualifier: "OIDAsURN",
			Value:     "urn:oid:1.2.840.10003.5.109.10",
		},
	}

	return opts
}

func facturaeTimestampFormatter(t time.Time) string {
	return t.Format("2006-01-02T15:04:05-07:00")
}

func facturaeIssuerSerializer(seq pkix.RDNSequence) string {
	return seq.String()
}
