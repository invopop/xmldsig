# Description of available XMLDSig and XAdES options

## XMLDSig options

These options allow configuring specific behavior at the XMLDSig level. To provide custom values, use `WithXMLDSigOptions` function with a struct overriding the defaults. Not using the function at all, or providing an empty struct, will result in default values being used.

| Field | Type | Description | Default |
| ----- | ---- | ----------- | ------- |
| `DataCanonicalizer` | `dsig.Canonicalizer` | Canonicalizer used on the XML being signed | Inclusive C14N10
| `DataHash` | `crypto.Hash` | Hash algorithm used on the XML being signed | SHA512
| `IncludeKeyValue` | `bool` | Whether to include the public key value (RSA or ECDSA) in `KeyInfo` | false |
| `ReferenceKeyInfoInSignedInfo` | `bool` | Whether to include hash of `KeyInfo` element in `SignedInfo` > `Reference` | false |
| `KeyInfoHash` | `crypto.Hash` | Hash algorithm used on `KeyInfo`; useful only when `IncludeKeyInfoInSignedInfo` is true | SHA512
| `KeyInfoCanonicalizer` | `dsig.Canonicalizer` | Canonicalizer used on `KeyInfo`; useful only when `IncludeKeyInfoInSignedInfo` is true | Inclusive C14N10
| `SignedInfoCanonicalizer` | `dsig.Canonicalizer` | Canonicalizer used on `SignedInfo` | Inclusive C14N10 |
| `SignedInfoHash` | `crypto.Hash` | Hash algorithm used on `SignedInfo` | SHA256 |

Defaults that need to be overridden for FacturaE:

- `ReferenceKeyInfoInSignedInfo` must be set to true
- `IncludeKeyValue` must be set to true

## XAdES options

These options allow configuring the XAdES level. To enable XAdES, use `WithXAdESOptions` function. A struct provided to the function will override the defaults. Providing an empty struct will result in fully using defaults.

| Field | Type | Description | Default |
| ----- | ---- | ----------- | ------- |
| `TimestampFormatter` | `func(time.Time) string` | Function to format timestamps | with `2006-01-02T15:04:05+00:00` (converted to UTC) |
| `IssuerSerializer` | `func(pkix.RDNSequence) string` | Function to serialize issuer information | `pkix.RDNSequence String` |
| `SigningCertificateHash` | `crypto.Hash` | Hash algorithm on the certificate, in `SignedSignatureProperties > SigningCertificate` | SHA512 |
| `SignedPropertiesCanonicalizer` | `dsig.Canonicalizer` | Canonicalizer used on `SignedProperties` in `SignedInfo` > `Reference` | Exclusive C14N10 |
| `SignedPropertiesHash` | `crypto.Hash` | Hash algorithm used on `SignedProperties` in `SignedInfo` > `Reference` | SHA512 |
| `Role` | `[]string` pointer to slice of strings | `SignedProperties > SignedSignatureProperties > SignerRole > ClaimedRoles > ClaimedRole` | empty slice |
| `DataObjectFormat` | `*DataObjectFormat` pointer to struct | `SignedProperties > SignedDataObjectProperties > DataObjectFormat` | `nil` |
| `PolicyIdentifier` | `*PolicyIdentifier` pointer to struct | `SignedProperties > SignedSignatureProperties > PolicyIdentifier` | `nil` |

For FacturaE:

- Format in `TimestampFormatter` should be `2006-01-02T15:04:05-07:00` (local time, not converted to UTC)
- `Role`, `DataObjectFormat` and `PolicyIdentifier` are required

For KSeF:

- Format in `TimestampFormatter` should be `2006-01-02T15:04:05.0000000+00:00` (converted to UTC)
- `IssuerSerializer` should be a custom function

TODO: there are more options in XAdES that can be added too.

## How to specify canonicalization

`dsig.Canonicalizer` is a Go interface fulfilled by various canonicalizers provided by `github.com/russellhaering/goxmldsig` library. For example:

- Inclusive C14N10 canonicalizer is `dsig.MakeC14N10RecCanonicalizer()`
- Exclusive C14N10 canonicalizer is `dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")`

There are more, and can be used in our library's custom configuration.

## Non-breaking differences

1. Signature element in KSeF reference signature has name `Signature` and in FacturaE `ds:Signature` - it's not a real difference, as in both cases the elements belongs to the same namespace, just in the first one it's unprefixed, and in the second one it's prefixed with `ds`.
2. Reference element, pointing at the outermost element of the XML being signed, in FacturaE, has attributes `Id` set to `Reference-test` and `Type` set to `http://uri.etsi.org/01903#SignedProperties`. In KSeF, these elements are not required, but including them does not cause any issues.
3. Signature element in KSeF reference signature has attribute `Id` set to `Signature`, while in FacturaE it is `Signature-test`. This element can have any arbitrary value, as long as it is passed in `xades:QualifyingProperties` in `Target` attribute. This applies to other ids.
4. KSeF, in the reference signature, for signed info canonicalizer, uses the non-exclusive canonicalizer, but the exclusive canonicalizer works as well.
