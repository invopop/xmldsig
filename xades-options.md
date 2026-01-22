# Description of available XAdES options

Available options are in struct having type `xmldsig.XAdESOptions`. Here's a list of the options:

| Field | Type | Description | Default | FacturaE | KSeF | 
| ----- | ---- | ----------- | ------- | -------- | ---- |
| `DataCanonicalizer` | `*dsig.Canonicalizer` | Canonicalizer used on the XML being signed, or nil to disable canonicalization | `nil` | `nil` | `dsig.MakeC14N10RecCanonicalizer()` |
| `DataHash` | `crypto.Hash` | Hash algorithm used on the XML being signed | `crypto.SHA512` | `crypto.SHA512` | `crypto.SHA512` |
| `TimestampFormatter` | `func(time.Time) string` | Function to format timestamps | with `2006-01-02T15:04:05Z` | with `2006-01-02T15:04:05-07:00` | with `2006-01-02T15:04:05.0000000+00:00` |
| `IssuerSerializer` | `func(pkix.RDNSequence) string` | Function to serialize issuer information | `pkix.Name FillFromRDNSequence > pkix.Name String` | `pkix.RDNSequence String` | see below |
| `SignedSignaturePropertiesCustomElements` | `*[]etree `| Custom elements to include in `SignedSignatureProperties` | `nil` | see below | `nil` |
| `SignedPropertiesCustomElements` | `*[]etree` | Custom elements to include in `SignedProperties` | `nil` | see below | `nil` |
| `SignedPropertiesCanonicalizer` | `*dsig.Canonicalizer` | Canonicalizer used on `SignedProperties` | `nil` | `nil` | `dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")` |
| `CertificateHash` | `crypto.Hash` | Hash algorithm on the certificate | `crypto.SHA512` | `crypto.SHA512` | `crypto.SHA512` |
| `SignedPropertiesHash` | `crypto.Hash` | Hash algorithm used on `SignedProperties` | `crypto.SHA512` | `crypto.SHA512` | `crypto.SHA512` |
| `KeyInfoHash` | `crypto.Hash` | Hash algorithm used on `KeyInfo`; zero disables adding `KeyInfo` to `SignedInfo` > `Reference` | `0` | `crypto.SHA512` | `0` |
| `SignedInfoCanonicalizer` | `*dsig.Canonicalizer` | Canonicalizer used on `SignedInfo` | `canonicalize` from `c14n.go` | `canonicalize` from `c14n.go` | `dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")` |
| `SignedInfoHash` | `crypto.Hash` | Hash algorithm used on `SignedInfo` | `crypto.SHA256` | `crypto.SHA256` | `crypto.SHA256` |
| `IncludeRSAKeyValue` | `bool` | Whether to include RSA key value in `KeyInfo` | `false` | `true` | `false` |

API-specific functions returning `xmldsig.XAdESOptions` (`xmldsig.WithFacturaE`, `xmldsig.WithKSeF`, more in the future) will include functions for filling certain struct fields with API-specific requirements, as appropriate.

## Notes

KSeF, in the reference signature, for signed info canonicalizer, uses non-exclusive canonicalizer. It also matches what's expected by XAdES.

But in the working code in gobl.ksef, we use exclusive canonicalizer, and non-exclusive one doesn't work.
