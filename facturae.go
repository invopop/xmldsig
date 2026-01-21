package xmldsig

import (
	"crypto"
	"crypto/x509/pkix"
	"time"
)

// XAdESSignerRole defines the accepted signer roles for FacturaE.
type XAdESSignerRole string

// String converts the XAdES role into a string.
func (r XAdESSignerRole) String() string {
	return string(r)
}

// XAdESPolicyConfig defines what policy details should be used for FacturaE.
type XAdESPolicyConfig struct {
	URL         string `json:"url"`                   // URL to the policy definition
	Description string `json:"description,omitempty"` // Optional human description
	Algorithm   string `json:"algorithm"`             // eg. SHA1 o SHA256
	Hash        string `json:"hash"`                  // Base64 encoded hash (usually provided with policy)
}

// FacturaEConfig stores options specific to Spanish FacturaE system.
type FacturaEConfig struct {
	Role        XAdESSignerRole    `json:"role"`
	Description string             `json:"description,omitempty"`
	Policy      *XAdESPolicyConfig `json:"policy"`
}

// Deprecated: use FacturaEConfig, as this type is specific to FacturaE. Old name XAdESConfig kept only for backwards compatibility with existing code.
type XAdESConfig = FacturaEConfig

// Deprecated: use WithFacturaE, as this function is specific to FacturaE. Old name WithXAdES kept only for backwards compatibility with existing code.
func WithXAdES(config *XAdESConfig) Option {
	return WithFacturaE(config)
}

// WithFacturaE adds the FacturaE-specific XAdES policy with the suggested role.
func WithFacturaE(config *FacturaEConfig) Option {
	return func(o *options) error {
		o.xades = config
		o.xadesOptions = facturaeXAdESOptions()
		return nil
	}
}

func facturaeXAdESOptions() XAdESOptions {
	return XAdESOptions{
		DataCanonicalizer:                       nil,
		DataHash:                                crypto.SHA256,
		TimestampFormatter:                      facturaeTimestampFormatter,
		IssuerSerializer:                        facturaeIssuerSerializer,
		SignedSignaturePropertiesCustomElements: nil, // TODO implement
		SignedPropertiesCustomElements:          nil, // TODO implement
		SignedPropertiesCanonicalizer:           nil,
		CertificateHash:                         crypto.SHA256,
		SignedPropertiesHash:                    crypto.SHA256,
		KeyInfoHash:                             0,
		SignedInfoCanonicalizer:                 canonicalize,
		SignedInfoHash:                          crypto.SHA256,
		SignedInfoSignatureAlgorithm:            SignedInfoSignatureAlgorithmRSA,
	}
}

func facturaeTimestampFormatter(t time.Time) string {
	return t.Format("2006-01-02T15:04:05-07:00")
}

func facturaeIssuerSerializer(seq pkix.RDNSequence) string {
	return seq.String()
}
