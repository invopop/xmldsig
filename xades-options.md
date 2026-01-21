# Description of available XAdES options

Available options are in struct having type `xmldsig.XAdESOptions`. Here's a list of the options:

| Field | Type | Description | Default | FacturaE | KSeF | 
| ----- | ---- | ----------- | ------- | -------- | ---- |
| `DataCanonicalizer` | `*dsig.Canonicalizer` | Canonicalizer used on the XML being signed, or nil to disable canonicalization | `nil` | `nil` | `dsig.MakeC14N10RecCanonicalizer()` |
| `DataHash` | `crypto.Hash` | Hash algorithm used on the XML being signed | `crypto.SHA256` | `crypto.SHA256` | `crypto.SHA256` |
| `TimestampFormatter` | `func(time.Time) string` | Function to format timestamps | with `2006-01-02T15:04:05Z` | with `2006-01-02T15:04:05-07:00` | with `2006-01-02T15:04:05.0000000+00:00` |
| `IssuerSerializer` | `func(pkix.RDNSequence) string` | Function to serialize issuer information | `pkix.Name FillFromRDNSequence > pkix.Name String` | `pkix.RDNSequence String` | see below |
| `SignedSignaturePropertiesCustomElements` | `*[]etree `| Custom elements to include in `SignedSignatureProperties` | `nil` | see below | `nil` |
| `SignedPropertiesCustomElements` | `*[]etree` | Custom elements to include in `SignedProperties` | `nil` | see below | `nil` |
| `SignedPropertiesCanonicalizer` | `*dsig.Canonicalizer` | Canonicalizer used on `SignedProperties` | `nil` | `nil` | `dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")` |
| `CertificateHash` | `crypto.Hash` | Hash algorithm on the certificate | `crypto.SHA512` | `crypto.SHA256` | `crypto.SHA512` |
| `SignedPropertiesHash` | `crypto.Hash` | Hash algorithm used on `SignedProperties` | `crypto.SHA512` | `crypto.SHA256 `| `crypto.SHA512` |
| `KeyInfoHash` | `crypto.Hash` | Hash algorithm used on `KeyInfo`, or nil to disable adding `KeyInfo` to `SignedInfo` > `Reference` | `nil` | `nil` | `crypto.SHA512` |
| `SignedInfoCanonicalizer` | `*dsig.Canonicalizer` | Canonicalizer used on `SignedInfo` | `canonicalize` from `c14n.go` | `canonicalize` from `c14n.go` | `dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")` |
| `SignedInfoHash` | `crypto.Hash` | Hash algorithm used on `SignedInfo` | `crypto.SHA256` | `crypto.SHA256` | `crypto.SHA256` |
| `SignedInfoSignatureAlgorithm` | `string` | Signature algorithm used on `SignedInfo` | `RSA` | `RSA` | `RSA` |

API-specific functions returning `xmldsig.XAdESOptions` (`xmldsig.WithFacturaE`, `xmldsig.WithKSeF`, more in the future) will include functions for filling certain struct fields with API-specific requirements, as appropriate.
