# XML DSig

Partial implementation of the XML DSig and XAdES standards for Go. Accepts certificates in .p12/.pfx format and generates signatures typically used with UBL invoice documents or similar local standards.

[![Lint](https://github.com/MieszkoGulinski/xmldsig/actions/workflows/lint.yaml/badge.svg)](https://github.com/MieszkoGulinski/xmldsig/actions/workflows/lint.yaml)
[![Test Go](https://github.com/MieszkoGulinski/xmldsig/actions/workflows/test.yaml/badge.svg)](https://github.com/MieszkoGulinski/xmldsig/actions/workflows/test.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/MieszkoGulinski/xmldsig)](https://goreportcard.com/report/github.com/MieszkoGulinski/xmldsig)
[![GoDoc](https://godoc.org/github.com/MieszkoGulinski/xmldsig?status.svg)](https://godoc.org/github.com/MieszkoGulinski/xmldsig)
![Latest Tag](https://img.shields.io/github/v/tag/MieszkoGulinski/xmldsig)

## Available settings

The library supports multiple configuration options. It's possible to specify options such as:

- whether to attach QualifyingProperties element (XAdES) or not (XML DSig but without XAdES)
- what canonicalizers to use
- what hashes to use
- whether to include reference to KeyInfo in SignedInfo (some APIs require it, some don't)
- whether to include the public key value (RSA or ECDSA) in KeyInfo (some APIs require it, some don't)

For convenience, there are **predefined option builders**:

- `xmldsig.FacturaeXMLDSigOptions()` together with `xmldsig.FacturaeXAdESOptions()` for Spanish FacturaE
- `xmldsig.KSeFXAdESOptions()` for Polish KSeF (XMLDSig defaults already match the profile)

For other APIs, it's possible to provide appropriate settings by creating structs of type `xmldsig.XMLDSigOptions` and `xmldsig.XAdESOptions`, and passing them to `xmldsig.WithXMLDSigOptions` and `xmldsig.WithXAdESOptions` respectively. Using these functions is not compatible with predefined settings.

### Example of custom configuration

```go
xmlOpts := xmldsig.XMLDSigOptions{
	DataCanonicalizer:       dsig.MakeC14N10RecCanonicalizer(), // Canonicalize the XML that is signed
	DataHash:                crypto.SHA512,                     // Hash algorithm for the signed XML
	SignedInfoCanonicalizer: dsig.MakeC14N10RecCanonicalizer(), // Canonicalization algorithm for SignedInfo
	SignedInfoHash:          crypto.SHA256,                     // Hash algorithm for SignedInfo
	IncludeKeyValue:         false,                             // Whether to include the public key in KeyInfo
	ReferenceKeyInfoInSignedInfo: true,                         // Whether SignedInfo should reference KeyInfo
	KeyInfoCanonicalizer:         dsig.MakeC14N10RecCanonicalizer(),
	KeyInfoHash:                  crypto.SHA512,
}

xadesOpts := xmldsig.XAdESOptions{
	TimestampFormatter:            customTimestampFormatter,          // Timestamp formatter for SigningTime
	IssuerSerializer:              nil,                               // Serializer for issuer names, nil for default
	SignedPropertiesCanonicalizer:           dsig.MakeC14N10RecCanonicalizer(),
	SignedPropertiesHash:                    crypto.SHA512,
	SigningCertificateHash:                  crypto.SHA512,
}

signature, err := xmldsig.Sign(data,
	xmldsig.WithCertificate(cert),
	xmldsig.WithXMLDSigOptions(xmlOpts),
	xmldsig.WithXAdESOptions(xadesOpts),
)
```

Example of a custom timestamp formatter:

```go
func customTimestampFormatter(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.0000000+00:00")
}
```

## Usage Example

This example shows how to sign a document using the XAdES standard with Polish KSeF predefined settings. In KSeF, signing an XML is used when logging into the API.

```go
type AuthTokenRequest struct {
	XMLName       xml.Name `xml:"AuthTokenRequest"`
	XMLNamespace  string   `xml:"xmlns,attr"`
	XSI           string   `xml:"xmlns:xsi,attr"`
	XSD           string   `xml:"xmlns:xsd,attr"`
	Challenge     string   `xml:"Challenge"`
	ContextIdentifier *ContextIdentifier `xml:"ContextIdentifier"`
	Signature     *xmldsig.Signature `xml:"ds:Signature,omitempty"` // Add signature object!
}

func main() {
	authTokenRequest := &AuthTokenRequest{
		// ... fill in the rest of the fields as needed ...
	}

	data, _ := xml.Marshal(authTokenRequest)
	cert, _ := xmldsig.LoadCertificate("./invopop.p12", "invopop")
	authTokenRequest.Signature, _ = xmldsig.Sign(data,
		xmldsig.WithCertificate(cert),
		xmldsig.WithXAdESOptions(xmldsig.KSeFXAdESOptions()),
	)

	// Now output the data
	out, _ := xml.Marshal(authTokenRequest)
	fmt.Println(string(out))
}
```

This example shows how to sign a document using the XAdES standard with Spanish FacturaE predefined settings. Note that this system requires additional configuration parameters to generate additional elements in the signature.

```go
type SampleDoc struct {
	XMLName       xml.Name `xml:"test:SampleDoc"`
	TestNamespace string   `xml:"xmlns:test,attr"`
	Title         string
	Signature     *xmldsig.Signature `xml:"ds:Signature,omitempty"` // Add signature object!
}

func main() {
	doc := &SampleDoc{
		TestNamespace: "http://invopop.com/xml/test",
		Title:         "This is a test",
	}
	// Using XAdES FacturaE example policy config
	facturaeOptions := &xmldsig.FacturaEConfig{
		Role:        xmldsig.XAdESSignerRole("third party"),
		Description: "test",
		Policy: &xmldsig.FacturaEPolicyConfig{
			URL:         "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf",
			Description: "Política de Firma FacturaE v3.1",
			Algorithm:   "http://www.w3.org/2000/09/xmldsig#sha1",
			Hash:        "Ohixl6upD6av8N7pEvDABhEL6hM=",
		},
	}
	data, _ := xml.Marshal(doc)
	cert, _ := xmldsig.LoadCertificate("./invopop.p12", "invopop")
	doc.Signature, _ = xmldsig.Sign(data,
		xmldsig.WithCertificate(cert),
		xmldsig.WithXMLDSigOptions(xmldsig.FacturaeXMLDSigOptions()),
		xmldsig.WithXAdESOptions(xmldsig.FacturaeXAdESOptions(facturaeOptions)),
	)

	// Now output the data
	out, _ := xml.Marshal(doc)
	fmt.Println(string(out))
}
```

Support is also included for using a Time Stamp Authority (TSA). Simply add the following to the `Sign` options with the URL of the service you want to use:

```go
xmldsig.WithTimestamp(xmldsig.TimestampFreeTSA) // uses https://freetsa.org/tsr
```

Using this option requires XAdES support to be enabled (by calling `WithXAdESOptions`), as the timestamp is added to `QualifyingProperties` > `UnsignedProperties` > `SignatureTimestamp`.

## Certificates

Signing and certificates can be overwhelming. OpenSSL is the tool to use for clarifying what the situation is and this page has a useful set of commands: https://www.sslshopper.com/article-most-common-openssl-commands.html

This library requires certificates in PKCS12 DER format (`.pfx` or `.p12` extension). If you don't have something like that, use the OpenSSL tools to convert between X509 (`.pem`) format and PKCS12.

The order of certificates is important, the main certificate must come first. You can check order using the following command:

```
openssl pkcs12 -info -in keyStore.p12
```

It might be a good idea to try exporting and re-creating your existing PKCS12 files if in doubt. First extract to pem:

```
openssl pkcs12 -in invopop.p12 -out invopop.pem -nodes
```

Split the resulting `.pem` file into multiple parts for the key, certificate, and CA certificate(s) using your text editor. Then rebuild:

```
openssl pkcs12 -export -out invopop.p12 -inkey invopop.key -in invopop.crt -certfile invopop.ca
```

## Changes

### Add information about canonicalization method to SignedInfo

Before this change, the library was performing canonicalization on the signed data and `SignedProperties` elements, but was not adding appropriate `Transform` elements, describing the canonicalization method, to the `SignedInfo` element.

### Updated methods

- `xmldsig.WithXAdES` and `xmldsig.WithFacturaE` have been replaced by the combination of `xmldsig.WithXMLDSigOptions(xmldsig.FacturaeXMLDSigOptions())` and `xmldsig.WithXAdESOptions(xmldsig.FacturaeXAdESOptions(...))`.
- `xmldsig.WithKSeF` has been replaced by `xmldsig.WithXAdESOptions(xmldsig.KSeFXAdESOptions())` (XMLDSig defaults already meet the KSeF requirements).

## Copyright

This project is developed and maintained under the Apache 2.0 Open Source license by [Invopop](https://invopop.com).

Copyright 2021-2023 Invopop Ltd.
