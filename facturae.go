package xmldsig

import (
	"crypto/x509/pkix"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

// FacturaeXMLDSigOptions returns the XMLDSig defaults required by the FacturaE profile.
func FacturaeXMLDSigOptions() XMLDSigOptions {
	return XMLDSigOptions{
		IncludeKeyValue:              true,
		ReferenceKeyInfoInSignedInfo: true,
	}
}

// FacturaeXAdESOptions builds the FacturaE-specific XAdES configuration from the provided config.
func FacturaeXAdESOptions(opts XAdESOptions) XAdESOptions {
	opts.TimestampFormatter = facturaeTimestampFormatter
	opts.IssuerSerializer = facturaeIssuerSerializer
	opts.SignedPropertiesCanonicalizer = dsig.MakeC14N10RecCanonicalizer()

	if opts.DataObjectFormat == nil {
		opts.DataObjectFormat = &DataObjectFormat{}
	}
	opts.DataObjectFormat.Description = opts.Description
	opts.DataObjectFormat.MimeType = "text/xml"
	opts.DataObjectFormat.ObjectIdentifier = &ObjectIdentifier{
		Identifier: Identifier{
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
