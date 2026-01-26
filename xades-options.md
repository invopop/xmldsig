# Description of available XAdES options

Available options are in struct having type `xmldsig.XAdESOptions`. Here's a list of the options:

| Field | Type | Description | Default | FacturaE | KSeF | 
| ----- | ---- | ----------- | ------- | -------- | ---- |
| `DataCanonicalizer` | `dsig.Canonicalizer` | Canonicalizer used on the XML being signed | `dsig.MakeC14N10RecCanonicalizer()` | `dsig.MakeC14N10RecCanonicalizer()` | `dsig.MakeC14N10RecCanonicalizer()` |
| `DataHash` | `crypto.Hash` | Hash algorithm used on the XML being signed | `crypto.SHA512` | `crypto.SHA512` | `crypto.SHA512` |
| `TimestampFormatter` | `func(time.Time) string` | Function to format timestamps | with `2006-01-02T15:04:05-07:00` | with `2006-01-02T15:04:05-07:00` | with `2006-01-02T15:04:05.0000000+00:00` |
| `IssuerSerializer` | `func(pkix.RDNSequence) string` | Function to serialize issuer information | `pkix.Name FillFromRDNSequence > pkix.Name String` | `pkix.RDNSequence String` | see below |
| `AttachQualifyingProperties` | `bool` | Whether to add `QualifyingProperties` element | `false` | `true` | `true` |
| `SignedSignaturePropertiesCustomElements` | `*[]etree `| Custom elements to include in `SignedSignatureProperties` | `nil` | see below | `nil` |
| `SignedPropertiesCustomElements` | `*[]etree` | Custom elements to include in `SignedProperties` | `nil` | see below | `nil` |
| `SignedPropertiesCanonicalizer` | `*dsig.Canonicalizer` | Canonicalizer used on `SignedProperties` | `dsig.MakeC14N10RecCanonicalizer()` | `dsig.MakeC14N10RecCanonicalizer()` | `dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")` |
| `CertificateHash` | `crypto.Hash` | Hash algorithm on the certificate | `crypto.SHA512` | `crypto.SHA512` | `crypto.SHA512` |
| `SignedPropertiesHash` | `crypto.Hash` | Hash algorithm used on `SignedProperties` | `crypto.SHA512` | `crypto.SHA512` | `crypto.SHA512` |
| `KeyInfoHash` | `crypto.Hash` | Hash algorithm used on `KeyInfo`; zero disables adding `KeyInfo` to `SignedInfo` > `Reference` | `0` | `crypto.SHA512` | `0` |
| `SignedInfoCanonicalizer` | `dsig.Canonicalizer` | Canonicalizer used on `SignedInfo` | `dsig.MakeC14N10RecCanonicalizer()` | `dsig.MakeC14N10RecCanonicalizer()` | `dsig.MakeC14N10RecCanonicalizer()` |
| `SignedInfoHash` | `crypto.Hash` | Hash algorithm used on `SignedInfo` | `crypto.SHA256` | `crypto.SHA256` | `crypto.SHA256` |
| `IncludeRSAKeyValue` | `bool` | Whether to include RSA key value in `KeyInfo` | `false` | `true` | `false` |

API-specific functions returning `xmldsig.XAdESOptions` (`xmldsig.WithFacturaE`, `xmldsig.WithKSeF`, more in the future) will include functions for filling certain struct fields with API-specific requirements, as appropriate.

## Notes

By default `AttachQualifyingProperties` is `false`, so the library only produces XML DSig signatures. Setting it to `true` adds the `QualifyingProperties` element (XAdES). When disabled, options `SignedSignaturePropertiesCustomElements`, `SignedPropertiesCustomElements`, `SignedPropertiesCanonicalizer` have no effect.

## Differences to check

KSeF, in the reference signature, for signed info canonicalizer, uses the non-exclusive canonicalizer defined by the XAdES specification. A request known to be working used the exclusive canonicalizer.

## Non-breaking differences

1. Signature element in KSeF reference signature has name `Signature` and in FacturaE `ds:Signature` - it's not a real difference, as in both cases the elements belongs to the same namespace, just in the first one it's unprefixed, and in the second one it's prefixed with `ds`.
2. Reference element, pointing at the outermost element of the XML being signed, in FacturaE, has attributes `Id` set to `Reference-test` and `Type` set to `http://uri.etsi.org/01903#SignedProperties`. In KSeF, these elements are not required, but including them does not cause any issues.
3. Signature element in KSeF reference signature has attribute `Id` set to `Signature`, while in FacturaE it is `Signature-test`. This element can have any arbitrary value, as long as it is passed in `xades:QualifyingProperties` in `Target` attribute. This applies to other ids.
