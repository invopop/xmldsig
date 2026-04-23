package xmldsig

import (
	"crypto"
	"crypto/x509/pkix"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

// XMLDSigConfig configures canonicalization, hashing, and KeyInfo handling for raw XML DSig signatures.
type XMLDSigConfig struct {
	DataCanonicalizer                 dsig.Canonicalizer
	DataHash                          crypto.Hash
	IncludeKeyValue                   bool
	ReferenceKeyInfoInSignedInfo      bool
	KeyInfoHash                       crypto.Hash
	KeyInfoCanonicalizer              dsig.Canonicalizer
	SignedInfoCanonicalizer           dsig.Canonicalizer
	SignedInfoHash                    crypto.Hash
	OmitDocumentReferenceType         bool
	OmitDataCanonicalizationTransform bool
	DocumentTransforms                []*AlgorithmMethod
	PreHashTransforms                 func([]byte) ([]byte, error)
}

// XAdESConfig configures the XAdES-specific properties.
type XAdESConfig struct {
	// Configuration for XAdES always present fields
	TimestampFormatter            func(time.Time) string
	IssuerSerializer              func(pkix.RDNSequence) string
	SigningCertificateHash        crypto.Hash
	SignedPropertiesCanonicalizer dsig.Canonicalizer
	SignedPropertiesHash          crypto.Hash

	// XAdES-specific optional XML fields
	OmitSignedPropertiesTransforms bool
	Role                           XAdESSignerRole
	Description                    string
	DataObjectFormat               *DataObjectFormat
	Policy                         *XAdESPolicyConfig
	IncludeCaChain                 bool
}

// normalizeXMLDSigConfig fills missing XMLDSig values with defaults.
func normalizeXMLDSigConfig(opts XMLDSigConfig) XMLDSigConfig {
	if opts.DataCanonicalizer == nil {
		opts.DataCanonicalizer = dsig.MakeC14N10RecCanonicalizer()
	}
	if opts.DataHash == 0 {
		opts.DataHash = crypto.SHA512
	}
	if opts.KeyInfoCanonicalizer == nil {
		opts.KeyInfoCanonicalizer = dsig.MakeC14N10RecCanonicalizer()
	}
	if opts.KeyInfoHash == 0 {
		opts.KeyInfoHash = crypto.SHA512
	}
	if opts.SignedInfoCanonicalizer == nil {
		opts.SignedInfoCanonicalizer = dsig.MakeC14N10RecCanonicalizer()
	}
	if opts.SignedInfoHash == 0 {
		opts.SignedInfoHash = crypto.SHA256
	}
	if len(opts.DocumentTransforms) == 0 {
		opts.DocumentTransforms = []*AlgorithmMethod{{Algorithm: dsig.EnvelopedSignatureAltorithmId.String()}}
	}
	return opts
}

// normalizeXAdESConfig fills missing XAdES values with defaults.
func normalizeXAdESConfig(opts *XAdESConfig) *XAdESConfig {
	if opts == nil {
		// XAdES is not enabled, don't set defaults
		return nil
	}

	if opts.TimestampFormatter == nil {
		opts.TimestampFormatter = defaultTimestampFormatter
	}
	if opts.IssuerSerializer == nil {
		opts.IssuerSerializer = defaultIssuerSerializer
	}
	if opts.SigningCertificateHash == 0 {
		opts.SigningCertificateHash = crypto.SHA512
	}
	if opts.SignedPropertiesCanonicalizer == nil {
		opts.SignedPropertiesCanonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	}
	if opts.SignedPropertiesHash == 0 {
		opts.SignedPropertiesHash = crypto.SHA512
	}
	return opts
}

var defaultTimestampFormatter = func(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05+00:00") // ISO 8601 with timezone
}

func defaultIssuerSerializer(seq pkix.RDNSequence) string {
	var name pkix.Name
	name.FillFromRDNSequence(&seq)
	return name.String()
}
