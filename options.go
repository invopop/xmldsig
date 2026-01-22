package xmldsig

import (
	"crypto"
	"crypto/x509/pkix"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// XAdESOptions allows low-level control over how hashes and canonicalization
// are performed when generating extended signatures.
type XAdESOptions struct {
	DataCanonicalizer                       dsig.Canonicalizer
	DataHash                                crypto.Hash
	TimestampFormatter                      func(time.Time) string
	IssuerSerializer                        func(pkix.RDNSequence) string
	SignedSignaturePropertiesCustomElements *[]*etree.Element
	SignedPropertiesCustomElements          *[]*etree.Element
	SignedPropertiesCanonicalizer           dsig.Canonicalizer
	CertificateHash                         crypto.Hash
	SignedPropertiesHash                    crypto.Hash
	KeyInfoHash                             crypto.Hash // 0 to disable adding Reference to KeyInfo
	SignedInfoCanonicalizer                 dsig.Canonicalizer
	SignedInfoHash                          crypto.Hash
	IncludeRSAKeyValue                      bool
}

// normalizeXAdESOptions fills missing values with defaults.
func normalizeXAdESOptions(opts *XAdESOptions) *XAdESOptions {
	if opts == nil {
		opts = &XAdESOptions{}
	}

	if opts.DataHash == 0 {
		opts.DataHash = crypto.SHA512
	}
	if opts.TimestampFormatter == nil {
		opts.TimestampFormatter = defaultTimestampFormatter
	}
	if opts.IssuerSerializer == nil {
		opts.IssuerSerializer = defaultIssuerSerializer
	}
	if opts.CertificateHash == 0 {
		opts.CertificateHash = crypto.SHA512
	}
	if opts.SignedPropertiesHash == 0 {
		opts.SignedPropertiesHash = crypto.SHA512
	}
	if opts.SignedInfoCanonicalizer == nil {
		opts.SignedInfoCanonicalizer = dsig.MakeC14N10RecCanonicalizer()
	}
	if opts.SignedInfoHash == 0 {
		opts.SignedInfoHash = crypto.SHA256
	}
	return opts
}

var defaultTimestampFormatter = func(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func defaultIssuerSerializer(seq pkix.RDNSequence) string {
	var name pkix.Name
	name.FillFromRDNSequence(&seq)
	return name.String()
}
