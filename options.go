package xmldsig

import (
	"crypto"
	"crypto/x509/pkix"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

// ECDSAFormat controls how ECDSA signature bytes are encoded in the SignatureValue element.
type ECDSAFormat string

const (
	// ECDSAFormatConcatenated encodes the signature as r||s (the W3C XML DSig standard format).
	ECDSAFormatConcatenated ECDSAFormat = "concatenated"
	// ECDSAFormatDER keeps the raw ASN.1 DER encoding produced by the signer.
	// Required by ZATCA, whose validator expects DER rather than the W3C format.
	ECDSAFormatDER ECDSAFormat = "der"
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
	ECDSAFormat                       ECDSAFormat
	OmitDocumentReferenceType         bool
	OmitDataCanonicalizationTransform bool
	DocumentTransforms                []*AlgorithmMethod
	PreHashTransforms                 func([]byte) ([]byte, error)

	// ID overrides — when set, replace the default UUID-based IDs.
	// SignatureID           string // root ds:Signature Id (default: "Signature-{docID}-Signature")
	// SignedDataReferenceID string // document ds:Reference Id (default: "Reference-{docID}")
	// OmitSignatureValueID bool // suppress Id on ds:SignatureValue
	// OmitKeyInfoID        bool // suppress Id on ds:KeyInfo
	SignDocumentDigest bool // sign the first Reference DigestValue (double-SHA-256) instead of canonical SignedInfo
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

	// Digest encoding — when true, digests in XAdES elements are hex-encoded
	// before base64: base64(hex(hash)) instead of base64(hash).
	HexEncodeDigests bool
	// HashPEMText — when true, the signing certificate digest is computed
	// over the base64 PEM text instead of the raw DER bytes.
	HashPEMText bool

	// ID and structure overrides
	// SignedPropertiesID                string // override xades:SignedProperties Id (default: "Signature-{docID}-SignedProperties")
	// OmitQualifyingPropertiesID        bool   // suppress Id on xades:QualifyingProperties
	// TargetRaw                         bool   // use Target without "#" prefix
	// SignedPropertiesReferenceType     string // override Type on the SP ds:Reference (default: "http://uri.etsi.org/01903#SignedProperties")
	// MinimalSignedPropertiesNamespaces bool   // only include ds+xades namespaces in SP canonicalization (not all root namespaces)
	RawXMLSignedPropertiesDigest bool // skip C14N, hash raw XML serialization (required by ZATCA which uses dom4j asXML())
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
	if opts.ECDSAFormat == "" {
		opts.ECDSAFormat = ECDSAFormatConcatenated
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
