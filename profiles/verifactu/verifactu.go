// Package verifactu provides XMLDSig and XAdES configuration for Spain's
// VERI*FACTU invoicing system. It implements the XAdES Enveloped signature
// profile with the AGE (Administración General del Estado) signature policy
// as specified in the AEAT technical documentation v0.1.5.
package verifactu

import (
	"crypto"
	"time"

	"github.com/invopop/xmldsig"
	dsig "github.com/russellhaering/goxmldsig"
)

// AGE Signature Policy parameters
const (
	PolicyIdentifier = "urn:oid:2.16.724.1.3.1.1.2.1.9"
	PolicyURL        = "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf"
	PolicyAlgorithm  = "http://www.w3.org/2000/09/xmldsig#sha1"
	PolicyHash       = "G7roucf600+f03r/o0bAOQ6WAs0="
)

// XMLDSigConfig returns the VeriFactu-specific XMLDSig configuration.
func XMLDSigConfig() xmldsig.XMLDSigConfig {
	return xmldsig.XMLDSigConfig{
		DataCanonicalizer:                 dsig.MakeC14N10RecCanonicalizer(),
		DataHash:                          crypto.SHA256,
		IncludeKeyValue:                   true,
		SignedInfoCanonicalizer:           dsig.MakeC14N10RecCanonicalizer(),
		SignedInfoHash:                    crypto.SHA256,
		OmitDocumentReferenceType:         true,
		OmitDataCanonicalizationTransform: true,
	}
}

// XAdESConfig returns the VeriFactu-specific XAdES configuration.
func XAdESConfig() xmldsig.XAdESConfig {
	return xmldsig.XAdESConfig{
		TimestampFormatter:            verifactuTimestampFormatter,
		SigningCertificateHash:        crypto.SHA256,
		SignedPropertiesCanonicalizer: dsig.MakeC14N10RecCanonicalizer(),
		SignedPropertiesHash:          crypto.SHA256,
		IncludeCaChain:                true,
		Policy: &xmldsig.XAdESPolicyConfig{
			Identifier: PolicyIdentifier,
			URL:        PolicyURL,
			Algorithm:  PolicyAlgorithm,
			Hash:       PolicyHash,
		},
		DataObjectFormat: &xmldsig.DataObjectFormat{
			MimeType: "text/xml",
			Encoding: "UTF-8",
			ObjectIdentifier: &xmldsig.ObjectIdentifier{
				Identifier: xmldsig.Identifier{
					Value: "urn:oid:1.2.840.10003.5.109.10",
				},
			},
		},
	}
}

func verifactuTimestampFormatter(t time.Time) string {
	return t.Format("2006-01-02T15:04:05-07:00")
}
