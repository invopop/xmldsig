package xmldsig

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

// WithFacturaE adds the FacturaE-specific XAdES policy with the suggested role.
func WithFacturaE(config *FacturaEConfig) Option {
	return WithXAdES(config)
}

// Deprecated: use WithFacturaE, as this function is specific to FacturaE. Old name WithXAdES kept only for backwards compatibility with existing code.
func WithXAdES(config *XAdESConfig) Option {
	return func(o *options) error {
		o.xades = config
		return nil
	}
}
