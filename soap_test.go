package xmldsig_test

import (
	"encoding/xml"
	"testing"

	"github.com/invopop/xmldsig"
	"github.com/stretchr/testify/assert"
)

type SampleSOAPOp struct {
	XMLName       xml.Name `xml:"test:SampleOp"`
	TestNamespace string   `xml:"xmlns:test,attr"`
	Title         string
}

func TestSOAPSign(t *testing.T) {
	t.Run("should return error if no certificate found", func(t *testing.T) {
		data := getSoapOpData()
		opts := []xmldsig.Option{
			xmldsig.WithNamespace("web", "https://webservice.face.gob.es"),
		}

		_, err := xmldsig.SignSOAP(data, opts...)

		assert.ErrorContains(t, err, "cannot sign without a certificate")
	})

	t.Run("should sign a SOAP document", func(t *testing.T) {
		data := getSoapOpData()
		certificate, _ := getCertificate()
		opts := []xmldsig.Option{
			xmldsig.WithCertificate(certificate),
			xmldsig.WithNamespace("web", "https://webservice.face.gob.es"),
		}

		securityElement, err := xmldsig.SignSOAP(data, opts...)

		assert.NoError(t, err)
		assert.NotNil(t, securityElement)
		assert.NotEmpty(t, securityElement.Signature.Value.Value)
	})

	t.Run("should add certificate info to signature", func(t *testing.T) {
		data := getSoapOpData()
		certificate, _ := getCertificate()
		opts := []xmldsig.Option{
			xmldsig.WithCertificate(certificate),
			xmldsig.WithNamespace("web", "https://webservice.face.gob.es"),
		}

		securityElement, _ := xmldsig.SignSOAP(data, opts...)

		assert.NotNil(t, securityElement.BinarySecurityToken.Value)
		keyInfo := securityElement.Signature.KeyInfo
		assert.NotNil(t, keyInfo.SecurityTokenReference)
		assert.Equal(t, keyInfo.SecurityTokenReference.Reference.URI, "#"+securityElement.BinarySecurityToken.ID)
	})

	t.Run("should sign the timestamp", func(t *testing.T) {
		data := getSoapOpData()
		certificate, _ := getCertificate()
		opts := []xmldsig.Option{
			xmldsig.WithCertificate(certificate),
			xmldsig.WithNamespace("web", "https://webservice.face.gob.es"),
		}

		securityElement, _ := xmldsig.SignSOAP(data, opts...)

		assert.NotNil(t, securityElement.Timestamp)
		assert.Equal(t, securityElement.Signature.SignedInfo.Reference[0].URI, "#"+securityElement.Timestamp.ID)
	})

	t.Run("should sign the soap op body", func(t *testing.T) {
		data := getSoapOpData()
		certificate, _ := getCertificate()
		opts := []xmldsig.Option{
			xmldsig.WithDocID("my-doc-id"),
			xmldsig.WithCertificate(certificate),
			xmldsig.WithNamespace("web", "https://webservice.face.gob.es"),
		}

		securityElement, _ := xmldsig.SignSOAP(data, opts...)

		assert.Equal(t, securityElement.Signature.SignedInfo.Reference[1].URI, "#BodyId-my-doc-id")
	})
}

func getSoapOpData() []byte {
	soap := &SampleSOAPOp{
		TestNamespace: "http://invopop.com/xml/test",
		Title:         "This is a test",
	}
	data, _ := xml.Marshal(soap)

	return data
}
