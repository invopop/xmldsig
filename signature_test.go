package xmldsig_test

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/xml"
	"os"
	"testing"
	"time"

	"github.com/invopop/xmldsig"
	"github.com/invopop/xmldsig/profiles/facturae"
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
		assert.Contains(t, signature.Value.Value, "TeFqLLA7swOs10oCartohVMMQv+KxJCQbRvgQB1sRWtB4yNkedeNPYL8C6EGSoTPKcVmPmJ486D5HrwEeP0OuJ2bGqdk2mrse6ooVt7oJ9jh/D3YypUUIA9bCCKaMZISvLrOcz9eLcUf+VNP++B4xlweBtgqBkKEMzPp6EEoFzLB6cNYVU3/WjALy3hscJ0lJ/oPL3DDxyguJ4nvOeGZcLTScalWOF5rDOC5LbsleENn39UdHPEzVfRk2sIICHdAxU+YXaMKXTRjWlS/XjvE0+h7VRLW0wCbFE6i38FNuuuKTosic92lYvNnl80ffP0ASrc//W4h7FAL9MlSORiHTw==")
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

		sp := signature.Object.QualifyingProperties.SignedProperties
		if sp == nil || sp.SignedSignatureProperties == nil {
			t.Fatalf("SignedProperties element missing")
		}
		assert.Nil(t, sp.SignedSignatureProperties.SignerRole)
	})

	t.Run("should set a signer role when provided", func(t *testing.T) {
		xmlOpt, xadesOpt := facturaeOptions(xadesConfig())
		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmlOpt,
			xadesOpt,
		)
		assert.Nil(t, err)

		sp := signature.Object.QualifyingProperties.SignedProperties
		if sp == nil || sp.SignedSignatureProperties == nil {
			t.Fatalf("SignedProperties element missing")
		}
		if assert.NotNil(t, sp.SignedSignatureProperties.SignerRole) &&
			assert.NotNil(t, sp.SignedSignatureProperties.SignerRole.ClaimedRoles) {
			require.Len(t, sp.SignedSignatureProperties.SignerRole.ClaimedRoles.ClaimedRole, 1)
			assert.Equal(t, "third party", sp.SignedSignatureProperties.SignerRole.ClaimedRoles.ClaimedRole[0])
		}
	})

	t.Run("should set appropriate formatted time and id in signed properties", func(t *testing.T) {
		xmlOpt, xadesOpt := facturaeOptions(xadesConfig())
		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmlOpt,
			xadesOpt,
			xmldsig.WithDocID("test"),
			xmldsig.WithCurrentTime(func() time.Time {
				return time.Date(2024, 3, 15, 10, 11, 12, 0, time.UTC)
			}),
		)
		assert.Nil(t, err)

		sp := signature.Object.QualifyingProperties.SignedProperties
		if sp == nil || sp.SignedSignatureProperties == nil {
			t.Fatalf("SignedProperties element missing")
		}

		assert.Equal(t, "xadesSignedProperties", sp.ID)
		assert.Equal(t, "2024-03-15T10:11:12+00:00", sp.SignedSignatureProperties.SigningTime)
	})

	t.Run("should include RSA key elements after signing", func(t *testing.T) {
		xmlOpt, xadesOpt := facturaeOptions(xadesConfig()) // includes IncludeKeyValue: true
		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmlOpt,
			xadesOpt,
		)
		require.NoError(t, err)

		require.NotNil(t, signature.KeyInfo, "KeyInfo should be present")
		require.NotNil(t, signature.KeyInfo.KeyValue, "KeyValue should be present")
		require.NotNil(t, signature.KeyInfo.KeyValue.RSA, "RSAKeyValue should be present")
		assert.NotEmpty(t, signature.KeyInfo.KeyValue.RSA.Modulus, "Modulus should not be empty")
		assert.NotEmpty(t, signature.KeyInfo.KeyValue.RSA.Exponent, "Exponent should not be empty")
	})

	t.Run("should include policy identifier and SPURI when both provided", func(t *testing.T) {
		cfg := xmldsig.XAdESConfig{
			Policy: &xmldsig.XAdESPolicyConfig{
				Identifier: "urn:oid:2.16.724.1.3.1.1.2.1.9",
				URL:        "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf",
				Algorithm:  "http://www.w3.org/2000/09/xmldsig#sha1",
				Hash:       "G7roucf600+f03r/o0bAOQ6WAs0=",
			},
		}

		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmldsig.WithXAdESConfig(cfg),
		)
		require.NoError(t, err)

		sp := signature.Object.QualifyingProperties.SignedProperties
		require.NotNil(t, sp)
		require.NotNil(t, sp.SignedSignatureProperties.SignaturePolicyIdentifier)

		pid := sp.SignedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyID
		assert.Equal(t, "urn:oid:2.16.724.1.3.1.1.2.1.9", pid.SigPolicyID.Identifier.Value)
		assert.Equal(t, "G7roucf600+f03r/o0bAOQ6WAs0=", pid.SigPolicyHash.DigestValue)

		require.NotNil(t, pid.SigPolicyQualifiers)
		require.Len(t, pid.SigPolicyQualifiers.SigPolicyQualifier, 1)
		assert.Equal(t, "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf",
			pid.SigPolicyQualifiers.SigPolicyQualifier[0].SPURI)
	})

	t.Run("should use dom4j signed properties serialization when flag is set", func(t *testing.T) {
		xadesCfg := facturae.XAdESConfig(xadesConfig())
		xadesCfg.Dom4jSignedProperties = true

		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmldsig.WithXMLDSigConfig(facturae.XMLDSigConfig()),
			xmldsig.WithXAdESConfig(xadesCfg),
		)
		require.NoError(t, err)

		spRef := findSignedPropertiesReference(signature)
		require.NotNil(t, spRef)

		spBytes, err := xml.Marshal(signature.Object.QualifyingProperties.SignedProperties)
		require.NoError(t, err)
		dom4j, err := xmldsig.SerializeDom4jSignedProperties(spBytes)
		require.NoError(t, err)

		// facturae's SignedPropertiesHash defaults to SHA-512 and digests are
		// base64-encoded (HexEncodeDigests is false).
		want := sha512.Sum512(dom4j)
		assert.Equal(t,
			base64.StdEncoding.EncodeToString(want[:]),
			spRef.DigestValue,
			"DigestValue should match base64(sha512(SerializeDom4jSignedProperties(spBytes)))",
		)

		// Sanity check: without the flag the digest differs.
		xmlOpt, xadesOpt := facturaeOptions(xadesConfig())
		baseline, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmlOpt,
			xadesOpt,
		)
		require.NoError(t, err)
		baselineSP := findSignedPropertiesReference(baseline)
		require.NotNil(t, baselineSP)
		assert.NotEqual(t, baselineSP.DigestValue, spRef.DigestValue)
	})

	t.Run("should not include policy qualifiers when only URL provided", func(t *testing.T) {
		cfg := xmldsig.XAdESConfig{
			Policy: &xmldsig.XAdESPolicyConfig{
				URL:       "http://example.com/policy.pdf",
				Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
				Hash:      "abc123=",
			},
		}

		signature, err := xmldsig.Sign(data,
			xmldsig.WithCertificate(certificate),
			xmldsig.WithXAdESConfig(cfg),
		)
		require.NoError(t, err)

		pid := signature.Object.QualifyingProperties.SignedProperties.
			SignedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyID
		assert.Equal(t, "http://example.com/policy.pdf", pid.SigPolicyID.Identifier.Value)
		assert.Nil(t, pid.SigPolicyQualifiers)
	})

}

func xadesConfig() xmldsig.XAdESConfig {
	return xmldsig.XAdESConfig{
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

func facturaeOptions(cfg xmldsig.XAdESConfig) (xmldsig.Option, xmldsig.Option) {
	return xmldsig.WithXMLDSigConfig(facturae.XMLDSigConfig()),
		xmldsig.WithXAdESConfig(facturae.XAdESConfig(cfg))
}

func getCertificate() (*xmldsig.Certificate, error) {
	return xmldsig.LoadCertificate(testCertificateFile, testCertificatePass)
}

func findSignedPropertiesReference(sig *xmldsig.Signature) *xmldsig.Reference {
	if sig == nil || sig.SignedInfo == nil {
		return nil
	}
	for _, r := range sig.SignedInfo.Reference {
		if r.Type == "http://uri.etsi.org/01903#SignedProperties" {
			return r
		}
	}
	return nil
}

func getTimestamp(signature *xmldsig.Signature) string {
	return signature.Object.QualifyingProperties.
		UnsignedProperties.SignatureTimestamp.EncapsulatedTimeStamp
}
