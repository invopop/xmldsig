# XML DSig

Partial implementation of the XML DSig and XAdES standards for Go. Accepts certificates in .p12/.pfx format and generates signatures typically used with UBL invoice documents or similar local standards.

[![Lint](https://github.com/invopop/xmldsig/actions/workflows/lint.yaml/badge.svg)](https://github.com/invopop/xmldsig/actions/workflows/lint.yaml)
[![Test Go](https://github.com/invopop/xmldsig/actions/workflows/test.yaml/badge.svg)](https://github.com/invopop/xmldsig/actions/workflows/test.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/invopop/xmldsig)](https://goreportcard.com/report/github.com/invopop/xmldsig)
[![GoDoc](https://godoc.org/github.com/invopop/xmldsig?status.svg)](https://godoc.org/github.com/invopop/xmldsig)
![Latest Tag](https://img.shields.io/github/v/tag/invopop/xmldsig)

## Predefined settings

The library supports multiple configuration options. For convenience, there are predefined settings:

- `xmldsig.WithFacturaE` - Spanish FacturaE
- `xmldsig.WithKSeF` - Polish KSeF

For other standards, provide appropriate settings using the generic `xmldsig.WithRawOptions` method.

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

The following types and methods were renamed,  as they were accepting options specific to Spanish FacturaE, not general XAdES options:

- `xmldsig.XAdESConfig` to `xmldsig.FacturaEConfig`
- `xmldsig.WithXAdES` to `xmldsig.WithFacturaE`
- `xmldsig.XAdESPolicyConfig` to `xmldsig.FacturaEPolicyConfig`

Old names are still kept in the code as aliases of the new names, but are marked as deprecated.

## Copyright

This project is developed and maintained under the Apache 2.0 Open Source license by [Invopop](https://invopop.com).

Copyright 2021-2023 Invopop Ltd.
