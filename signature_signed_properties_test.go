package xmldsig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	internalTestCertificateFile = "./certs/facturae.p12"
	internalTestCertificatePass = "invopop"
)

func TestBuildSignedPropertiesElement_Default(t *testing.T) {
	sig := createCommonSignature()
	el := buildTestSignedPropertiesElement(t, sig)

	require.Equal(t, "Signature-test-SignedProperties", el.ID)
	require.NotNil(t, el.SignedSignatureProperties)
	require.Equal(t, "2024-03-15T10:11:12Z", el.SignedSignatureProperties.SigningTime)
	require.Nil(t, el.SignedDataObjectProperties)
}

func buildTestSignedPropertiesElement(t *testing.T, sig *Signature) *SignedProperties {
	cert, err := LoadCertificate(internalTestCertificateFile, internalTestCertificatePass)
	require.NoError(t, err)

	sig.opts.cert = cert

	el, err := sig.buildSignedPropertiesElement()
	require.NoError(t, err)
	require.NotNil(t, el)
	return el
}

// createCommonSignature creates common settings needed for testing signed properties
func createCommonSignature() *Signature {
	fixedTime := time.Date(2024, 3, 15, 10, 11, 12, 0, time.UTC)
	sig := &Signature{
		opts: &options{
			docID: "test",
			timeNow: func() time.Time {
				return fixedTime
			},
		},
	}
	sig.opts.xmlOptions = *normalizeXMLDSigOptions(nil)
	sig.opts.xadesOptions = normalizeXAdESOptions(&XAdESConfig{
		TimestampFormatter: func(time.Time) string {
			return fixedTime.Format(time.RFC3339)
		},
	})
	return sig
}
