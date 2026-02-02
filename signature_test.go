package xmldsig_test

import (
	"encoding/xml"
	"os"
	"testing"
	"time"

	"github.com/MieszkoGulinski/xmldsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type SampleDoc struct {
	XMLName       xml.Name `xml:"test:SampleDoc"`
	TestNamespace string   `xml:"xmlns:test,attr"`
	Title         string
	Signature     *xmldsig.Signature `xml:"ds:Signature,omitempty"`
}

func TestSignature(t *testing.T) {
	doc := &SampleDoc{
		TestNamespace: "http://invopop.com/xml/test",
		Title:         "This is a test",
	}

	data, err := xml.Marshal(doc)
	require.NoError(t, err)

	certificate, err := getCertificate()
	require.NoError(t, err)

	t.Run("should return a signature", func(t *testing.T) {
		xmlOpt, xadesOpt := facturaeOptions(xadesConfig())
		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmlOpt,
			xadesOpt,
		)
		assert.Nil(t, err)
		assert.NotEmpty(t, signature.Value.Value)

		doc.Signature = signature

		out, err := xml.Marshal(doc)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile("./data/out/sample_doc.xml", out, 0644))
	})

	t.Run("should not add the timestamp when parameter is false", func(t *testing.T) {
		xmlOpt, xadesOpt := facturaeOptions(xadesConfig())
		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmlOpt,
			xadesOpt,
		)
		assert.Nil(t, err)
		assert.Nil(t, signature.Object.QualifyingProperties.UnsignedProperties)
	})

	t.Run("should add the timestamp when parameter is true", func(t *testing.T) {
		xmlOpt, xadesOpt := facturaeOptions(xadesConfig())
		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmlOpt,
			xadesOpt,
			xmldsig.WithTimestamp(xmldsig.TimestampFreeTSA),
		)
		require.NoError(t, err)
		assert.NotEmpty(t, getTimestamp(signature))
	})

	t.Run("should support setting a fixed signing time", func(t *testing.T) {
		ts, err := time.Parse(time.RFC3339, "2022-08-05T13:51:00+02:00")
		require.NoError(t, err)
		xmlOpt, xadesOpt := facturaeOptions(xadesConfig())
		signature, err := xmldsig.Sign(data,
			xmldsig.WithDocID("test"),
			xmldsig.WithCertificate(certificate),
			xmlOpt,
			xadesOpt,
			xmldsig.WithCurrentTime(func() time.Time {
				return ts
			}),
		)
		assert.Nil(t, err)
		// This is mostly useful for getting back fixed results, so
		// we can safely compare the final signature here.
		assert.Contains(t, signature.Value.Value, "FI/dYHsrKBKKTkJWYXHk/fNd4H19VnReFF+H8mD4uFva0RYUzC+RnfY2LiBtmXEtNfQ+PFmz+mV15sWWzyaqy9zYWX35GNFZLuWFleIRp0RsiHS6mV1gzphzVqyceVGKlKTH6zh6pQ9d/cX+15NMH0XE1Ephz4aFpaRb3WkehAWQ2csseYoKMrgCyg/kMzZRBJYcA9b6POa8ZOEcydIi3sdrt9S6e6Z+Msx1LsGOhvc1VQ0Hr1rKgkpS2uHswTB3UJrozT+fYOYK3y5DZJvxuJDAOlmCxniohjman7lkSdhEDZuDsJtqdnoi3dTe8pon0OtxdCiop+HH8nAV7CLTJg==")
	})

	t.Run("should not set a signer role when not provided", func(t *testing.T) {
		xades := xadesConfig()
		xades.Role = ""
		xmlOpt, xadesOpt := facturaeOptions(xades)
		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmlOpt,
			xadesOpt,
		)
		assert.Nil(t, err)

		sp := signature.Object.QualifyingProperties.SignedProperties.Element()
		if sp == nil {
			t.Fatalf("SignedProperties element missing")
		}
		roleElement := sp.FindElement("xades:SignedSignatureProperties/xades:SignerRole")
		assert.Nil(t, roleElement)
	})

	t.Run("should set a signer role when provided", func(t *testing.T) {
		xmlOpt, xadesOpt := facturaeOptions(xadesConfig())
		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmlOpt,
			xadesOpt,
		)
		assert.Nil(t, err)

		sp := signature.Object.QualifyingProperties.SignedProperties.Element()
		if sp == nil {
			t.Fatalf("SignedProperties element missing")
		}
		roleElement := sp.FindElement("xades:SignedSignatureProperties/xades:SignerRole/xades:ClaimedRoles/xades:ClaimedRole")
		if assert.NotNil(t, roleElement) {
			assert.Equal(t, "third party", roleElement.Text())
		}
	})
}

func xadesConfig() *xmldsig.FacturaEConfig {
	return &xmldsig.FacturaEConfig{
		Role:        xmldsig.XAdESSignerRole("third party"),
		Description: "test",
		Policy: &xmldsig.XAdESPolicyConfig{
			URL:         "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf",
			Description: "Política de Firma FacturaE v3.1",
			Algorithm:   "http://www.w3.org/2000/09/xmldsig#sha1",
			Hash:        "Ohixl6upD6av8N7pEvDABhEL6hM=",
		},
	}
}

func facturaeOptions(cfg *xmldsig.FacturaEConfig) (xmldsig.Option, xmldsig.Option) {
	return xmldsig.WithXMLDSigOptions(xmldsig.FacturaeXMLDSigOptions()),
		xmldsig.WithXAdESOptions(xmldsig.FacturaeXAdESOptions(cfg))
}

func getCertificate() (*xmldsig.Certificate, error) {
	return xmldsig.LoadCertificate(testCertificateFile, testCertificatePass)
}

/*
func getExampleXML(t *testing.T) []byte {
	data, err := os.ReadFile("./data/invoice-vat.xml")
	require.NoError(t, err)

	return data
}
*/

func getTimestamp(signature *xmldsig.Signature) string {
	return signature.Object.QualifyingProperties.
		UnsignedProperties.SignatureTimestamp.EncapsulatedTimeStamp
}
