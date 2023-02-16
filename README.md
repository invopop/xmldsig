# XML DSig

Partial implementation of the XML DSig standard for Go. Can be used to manage certificates in .p12 format and generate signatures typically used with UBL invoice documents or similar local standards.

[![Lint](https://github.com/invopop/xmldsig/actions/workflows/lint.yaml/badge.svg)](https://github.com/invopop/xmldsig/actions/workflows/lint.yaml)
[![Test Go](https://github.com/invopop/xmldsig/actions/workflows/test.yaml/badge.svg)](https://github.com/invopop/xmldsig/actions/workflows/test.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/invopop/xmldsig)](https://goreportcard.com/report/github.com/invopop/xmldsig)
[![GoDoc](https://godoc.org/github.com/invopop/xmldsig?status.svg)](https://godoc.org/github.com/invopop/xmldsig)
![Latest Tag](https://img.shields.io/github/v/tag/invopop/xmldsig)

## NOTES

- Canonicalisation: at the moment is _EXTREMELY_ limited. It'll handle missing namespaces on root elements, but you **MUST** ensure the Go structures (`type struct`) you intend to Marshal contain attributes in their canonical order: first namespaces, then regular attributes.

## Usage Example

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
	xades := &xmldsig.XAdESConfig{
		Role:        xmldsig.XAdESThirdParty,
		Description: "test",
		Policy: &xmldsig.XAdESPolicyConfig{
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
		xmldsig.WithXAdES(xades),
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

This library requires certificates in PKCS12 DER format (`.pki` or `.p12` extension). If you don't have something like that, use the OpenSSL tools to convert between X509 (`.pem`) format and PKCS12.

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

## Copyright

This project is developed and maintained under the Apache 2.0 Open Source license by [Invopop](https://invopop.com).

Copyright 2021-2023 Invopop Ltd.
