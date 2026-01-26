package xmldsig

import (
	"crypto"
	"crypto/x509/pkix"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// XAdESSignerRole defines the accepted signer roles for FacturaE.
type XAdESSignerRole string

// String converts the XAdES role into a string.
func (r XAdESSignerRole) String() string {
	return string(r)
}

// FacturaEPolicyConfig defines what policy details should be used for FacturaE.
type FacturaEPolicyConfig struct {
	URL         string `json:"url"`                   // URL to the policy definition
	Description string `json:"description,omitempty"` // Optional human description
	Algorithm   string `json:"algorithm"`             // eg. SHA1 o SHA256
	Hash        string `json:"hash"`                  // Base64 encoded hash (usually provided with policy)
}

// Deprecated: use FacturaEPolicyConfig, as this type is specific to FacturaE. Old name XAdESPolicyConfig kept only for backwards compatibility with existing code.
type XAdESPolicyConfig = FacturaEPolicyConfig

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
		o.xadesOptions = facturaeXAdESOptions(config)
		return nil
	}
}

func facturaeXAdESOptions(config *FacturaEConfig) XAdESOptions {
	return XAdESOptions{
		DataCanonicalizer:                       dsig.MakeC14N10RecCanonicalizer(),
		DataHash:                                crypto.SHA512,
		TimestampFormatter:                      facturaeTimestampFormatter,
		IssuerSerializer:                        facturaeIssuerSerializer,
		AttachQualifyingProperties:              true,
		SignedSignaturePropertiesCustomElements: facturaeSignedSignaturePropertiesCustomElements(config),
		SignedPropertiesCustomElements:          facturaeSignedPropertiesCustomElements(config),
		SignedPropertiesCanonicalizer:           dsig.MakeC14N10RecCanonicalizer(),
		CertificateHash:                         crypto.SHA512,
		SignedPropertiesHash:                    crypto.SHA512,
		KeyInfoHash:                             crypto.SHA512,
		SignedInfoCanonicalizer:                 dsig.MakeC14N10RecCanonicalizer(),
		SignedInfoHash:                          crypto.SHA256,
		IncludeRSAKeyValue:                      true,
	}
}

func facturaeTimestampFormatter(t time.Time) string {
	return t.Format("2006-01-02T15:04:05-07:00")
}

func facturaeIssuerSerializer(seq pkix.RDNSequence) string {
	return seq.String()
}

func facturaeSignedSignaturePropertiesCustomElements(config *FacturaEConfig) *[]*etree.Element {
	if config == nil {
		return nil
	}

	var elements []*etree.Element

	if el := facturaeSignaturePolicyIdentifierElement(config.Policy); el != nil {
		elements = append(elements, el)
	}

	if config.Role != "" {
		elements = append(elements, facturaeSignerRoleElement(config.Role))
	}

	if len(elements) == 0 {
		return nil
	}

	return &elements
}

func facturaeSignaturePolicyIdentifierElement(policy *XAdESPolicyConfig) *etree.Element {
	if policy == nil {
		return nil
	}

	root := etree.NewElement("xades:SignaturePolicyIdentifier")
	signaturePolicyID := root.CreateElement("xades:SignaturePolicyId")

	sigPolicyID := signaturePolicyID.CreateElement("xades:SigPolicyId")
	sigPolicyID.CreateElement("xades:Identifier").SetText(policy.URL)
	sigPolicyID.CreateElement("xades:Description").SetText(policy.Description)

	sigPolicyHash := signaturePolicyID.CreateElement("xades:SigPolicyHash")
	digestMethod := sigPolicyHash.CreateElement("ds:DigestMethod")
	digestMethod.CreateAttr("Algorithm", policy.Algorithm)
	sigPolicyHash.CreateElement("ds:DigestValue").SetText(policy.Hash)

	return root
}

func facturaeSignerRoleElement(role XAdESSignerRole) *etree.Element {
	roleElement := etree.NewElement("xades:SignerRole")
	claimedRoles := roleElement.CreateElement("xades:ClaimedRoles")
	claimedRoles.CreateElement("xades:ClaimedRole").SetText(role.String())
	return roleElement
}

func facturaeSignedPropertiesCustomElements(config *FacturaEConfig) *[]*etree.Element {
	if config == nil {
		return nil
	}

	signedDataObjectProps := etree.NewElement("xades:SignedDataObjectProperties")

	dataObjectFormat := signedDataObjectProps.CreateElement("xades:DataObjectFormat")
	dataObjectFormat.CreateAttr("ObjectReference", "#Reference")
	dataObjectFormat.CreateElement("xades:Description").SetText(config.Description)

	objectIdentifier := dataObjectFormat.CreateElement("xades:ObjectIdentifier")
	identifier := objectIdentifier.CreateElement("xades:Identifier")
	identifier.CreateAttr("Qualifier", "OIDAsURN")
	identifier.SetText("urn:oid:1.2.840.10003.5.109.10")

	dataObjectFormat.CreateElement("xades:MimeType").SetText("text/xml")

	elements := []*etree.Element{signedDataObjectProps}
	return &elements
}
