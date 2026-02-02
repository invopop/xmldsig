package xmldsig

import (
	"crypto/x509/pkix"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

// FacturaESignerRole defines the accepted signer roles for FacturaE.
type FacturaESignerRole string

// Deprecated: Use FacturaESignerRole instead. Old name kept only for backwards compatibility with existing code.
type XAdESSignerRole = FacturaESignerRole

// String converts the XAdES role into a string.
func (r FacturaESignerRole) String() string {
	return string(r)
}

// FacturaEPolicyConfig defines what policy details should be used for FacturaE.
type FacturaEPolicyConfig struct {
	URL         string `json:"url"`                   // URL to the policy definition
	Description string `json:"description,omitempty"` // Optional human description
	Algorithm   string `json:"algorithm"`             // eg. SHA1 or SHA256
	Hash        string `json:"hash"`                  // Base64 encoded hash (usually provided with policy)
}

// Deprecated: use FacturaEPolicyConfig, as this type is specific to FacturaE. Old name XAdESPolicyConfig kept only for backwards compatibility with existing code.
type XAdESPolicyConfig = FacturaEPolicyConfig

// FacturaEConfig stores options specific to Spanish FacturaE system.
type FacturaEConfig struct {
	Role        FacturaESignerRole `json:"role"`
	Description string             `json:"description,omitempty"`
	Policy      *XAdESPolicyConfig `json:"policy"`
}

// Deprecated: use FacturaEConfig, as this type is specific to FacturaE. Old name XAdESConfig kept only for backwards compatibility with existing code.
type XAdESConfig = FacturaEConfig

// FacturaeXMLDSigOptions returns the XMLDSig defaults required by the FacturaE profile.
func FacturaeXMLDSigOptions() XMLDSigOptions {
	return XMLDSigOptions{
		IncludeKeyValue:              true,
		ReferenceKeyInfoInSignedInfo: true,
	}
}

// FacturaeXAdESOptions builds the FacturaE-specific XAdES configuration from the provided config.
func FacturaeXAdESOptions(config *FacturaEConfig) XAdESOptions {
	opts := XAdESOptions{
		TimestampFormatter:            facturaeTimestampFormatter,
		IssuerSerializer:              facturaeIssuerSerializer,
		SignedPropertiesCanonicalizer: dsig.MakeC14N10RecCanonicalizer(),
	}

	if config != nil {
		if config.Role != "" {
			roles := []string{config.Role.String()}
			opts.Role = &roles
		}
		opts.DataObjectFormat = &DataObjectFormat{
			Description: config.Description,
			ObjectIdentifier: &ObjectIdentifier{
				Identifier: Identifier{
					Qualifier: "OIDAsURN",
					Value:     "urn:oid:1.2.840.10003.5.109.10",
				},
			},
			MimeType: "text/xml",
		}
		if config.Policy != nil {
			opts.PolicyIdentifier = &PolicyIdentifier{
				Identifier: Identifier{
					Value: config.Policy.URL,
				},
				Description:           config.Policy.Description,
				DigestMethodAlgorithm: config.Policy.Algorithm,
				DigestValue:           config.Policy.Hash,
			}
		}
	}

	return opts
}

func facturaeTimestampFormatter(t time.Time) string {
	return t.Format("2006-01-02T15:04:05-07:00")
}

func facturaeIssuerSerializer(seq pkix.RDNSequence) string {
	return seq.String()
}
