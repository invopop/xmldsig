package xmldsig_test

import (
	"encoding/xml"
	"os"
	"testing"

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
			xmldsig.WithXAdES(xmldsig.XAdESThirdParty, "test"),
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
			xmldsig.WithXAdES(xmldsig.XAdESThirdParty, "test"),
		)
		assert.Nil(t, err)
		assert.Nil(t, signature.Object.QualifyingProperties.UnsignedProperties)
	})

	t.Run("should add the timestamp when parameter is true", func(t *testing.T) {
		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmldsig.WithXAdES(xmldsig.XAdESThirdParty, "test"),
			xmldsig.WithTimestamp(xmldsig.TimestampFreeTSA),
		)
		require.NoError(t, err)
		assert.NotEmpty(t, getTimestamp(signature))
	})
}

func getCertificate() (*xmldsig.Certificate, error) {
	return xmldsig.LoadCertificate(testCertificateFile, testCertificatePass)
}

func getExampleXML(t *testing.T) []byte {
	data, err := os.ReadFile("./data/invoice-vat.xml")
	require.NoError(t, err)

	return data
}

func getTimestamp(signature *xmldsig.Signature) string {
	return signature.Object.QualifyingProperties.
		UnsignedProperties.SignatureTimestamp.EncapsulatedTimeStamp
}
