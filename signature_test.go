package xmldsig_test

import (
	"encoding/xml"
	"os"
	"testing"
	"time"

	"github.com/invopop/xmldsig"
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
		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmldsig.WithXAdES(xadesConfig()),
		)
		assert.Nil(t, err)
		assert.NotEmpty(t, signature.Value.Value)

		doc.Signature = signature

		out, err := xml.Marshal(doc)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile("./data/out/sample_doc.xml", out, 0644))
	})

	t.Run("should not add the timestamp when parameter is false", func(t *testing.T) {
		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmldsig.WithXAdES(xadesConfig()),
		)
		assert.Nil(t, err)
		assert.Nil(t, signature.Object.QualifyingProperties.UnsignedProperties)
	})

	t.Run("should add the timestamp when parameter is true", func(t *testing.T) {
		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmldsig.WithXAdES(xadesConfig()),
			xmldsig.WithTimestamp(xmldsig.TimestampFreeTSA),
		)
		require.NoError(t, err)
		assert.NotEmpty(t, getTimestamp(signature))
	})

	t.Run("should support setting a fixed signing time", func(t *testing.T) {
		ts, err := time.Parse(time.RFC3339, "2022-08-05T13:51:00+02:00")
		require.NoError(t, err)
		signature, err := xmldsig.Sign(data,
			xmldsig.WithDocID("test"),
			xmldsig.WithCertificate(certificate),
			xmldsig.WithXAdES(xadesConfig()),
			xmldsig.WithCurrentTime(func() time.Time {
				return ts
			}),
		)
		assert.Nil(t, err)
		// This is mostly useful for getting back fixed results, so
		// we can safely compare the final signature here.
		assert.Contains(t, signature.Value.Value, "r1GyPRqPZN3LXZ7SKpENUtI7dSXA83aIlza7fG2c1XGnHOK4HNweEDifqg65owS6TYLn7eZtiUXMHN49CUnZ7YDo9O")
	})

	t.Run("should not set a signer role when not provided", func(t *testing.T) {
		xades := xadesConfig()
		xades.Role = ""
		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmldsig.WithXAdES(xades),
		)
		assert.Nil(t, err)
		assert.Nil(t, signature.Object.QualifyingProperties.SignedProperties.SignatureProperties.SignerRole)
	})

	t.Run("should set a signer role when provided", func(t *testing.T) {
		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmldsig.WithXAdES(xadesConfig()),
		)
		assert.Nil(t, err)
		assert.Equal(t,
			"third party",
			signature.Object.QualifyingProperties.SignedProperties.
				SignatureProperties.SignerRole.ClaimedRoles.ClaimedRole[0])
	})
}

func xadesConfig() *xmldsig.XAdESConfig {
	return &xmldsig.XAdESConfig{
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
