# XML DSig

Partial implementation of the XML DSig and XAdES standards for Go. Accepts certificates in .p12/.pfx format and generates signatures typically used with UBL invoice documents or similar local standards.

[![Lint](https://github.com/invopop/xmldsig/actions/workflows/lint.yaml/badge.svg)](https://github.com/invopop/xmldsig/actions/workflows/lint.yaml)
[![Test Go](https://github.com/invopop/xmldsig/actions/workflows/test.yaml/badge.svg)](https://github.com/invopop/xmldsig/actions/workflows/test.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/invopop/xmldsig)](https://goreportcard.com/report/github.com/invopop/xmldsig)
[![GoDoc](https://godoc.org/github.com/invopop/xmldsig?status.svg)](https://godoc.org/github.com/invopop/xmldsig)
![Latest Tag](https://img.shields.io/github/v/tag/invopop/xmldsig)

## Available settings

The library supports multiple configuration options. It's possible to specify options such as:

- whether to attach QualifyingProperties element (XAdES) or not (XML DSig but without XAdES)
- custom XML elements to include in SignedProperties and SignedSignatureProperties (some APIs require it, some don't)
- what canonicalizers to use
- what hashes to use
- whether to include reference to KeyInfo in SignedInfo (some APIs require it, some don't)
- whether to include RSA key value in KeyInfo (some APIs require it, some don't)

For convenience, there are **predefined** settings:

- `xmldsig.WithFacturaE` - Spanish FacturaE
- `xmldsig.WithKSeF` - Polish KSeF

For other APIs, it's possible to provide appropriate settings by creating a struct of type `xmldsig.XAdESOptions` manually, and passing it to `xmldsig.WithRawOptions` method. Note that using `xmldsig.WithRawOptions` is not compatible with using a predefined setting.

### Example of custom configuration

```go
	return XAdESOptions{
		AttachQualifyingProperties:              true,                              // Whether to attach QualifyingProperties element, containing XAdES-specific elements
		SignedSignaturePropertiesCustomElements: nil,                               // Custom elements to include in SignedSignatureProperties (nil to skip)
		SignedPropertiesCustomElements:          nil,                               // Custom elements to include in SignedProperties (nil to skip)
		DataCanonicalizer:                       dsig.MakeC14N10RecCanonicalizer(), // Canonicalization algorithm for the outermost element (inclusive and exclusive canonicalizers work identically anyway)
		DataHash:                                crypto.SHA512,                     // Hash algorithm for hashing the outermost element - the hash will then be included in a Reference element
		TimestampFormatter:                      customTimestampFormatter,          // Timestamp formatter for the Timestamp element
		IssuerSerializer:                        nil,                               // Serializer for the Issuer element in SignedProperties, containing information about certificate issuer (nil for default one)
		SignedPropertiesCanonicalizer:           dsig.MakeC14N10RecCanonicalizer(), // Canonicalization algorithm for the SignedProperties element
		SignedPropertiesHash:                    crypto.SHA512,											// Hash algorithm for the SignedProperties element
		CertificateHash:                         crypto.SHA512, 										// Hash algorithm for the certificate, for xades:CertDigest element
		KeyInfoCanonicalizer:                    nil, 															// Canonicalization algorithm for the KeyInfo element - must be non-nil to add reference to KeyInfo in SignedInfo
		KeyInfoHash:                             0, 																// Hash algorithm for the KeyInfo element - must be non-zero to add reference to KeyInfo in SignedInfo
		SignedInfoCanonicalizer:                 dsig.MakeC14N10RecCanonicalizer(), // Canonicalization algorithm for the SignedInfo element
		SignedInfoHash:                          crypto.SHA256,											// Hash algorithm for the SignedInfo element
		IncludeRSAKeyValue:                      false, 														// Whether to include RSA key value in KeyInfo
	}
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
		xmldsig.WithKSeF(),
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
	xades := &xmldsig.FacturaEConfig{
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
		xmldsig.WithFacturaE(xades),
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

Using this option requires `AttachQualifyingProperties` to be true, as the timestamp is added to `QualifyingProperties` > `UnsignedProperties` > `SignatureTimestamp` element.

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

### Renamed methods

The following types and methods were renamed, as they were accepting options specific to Spanish FacturaE, not general XAdES options:

- `xmldsig.XAdESConfig` to `xmldsig.FacturaEConfig`
- `xmldsig.WithXAdES` to `xmldsig.WithFacturaE`
- `xmldsig.XAdESPolicyConfig` to `xmldsig.FacturaEPolicyConfig`

Old names are still kept in the code as aliases of the new names, but are marked as deprecated.

## Copyright

This project is developed and maintained under the Apache 2.0 Open Source license by [Invopop](https://invopop.com).

Copyright 2021-2023 Invopop Ltd.
