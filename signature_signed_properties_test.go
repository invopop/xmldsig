package xmldsig

import (
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

const (
	internalTestCertificateFile = "./certs/facturae.p12"
	internalTestCertificatePass = "invopop"
)

func TestBuildSignedPropertiesElement_Default(t *testing.T) {
	sig := createCommonSignature()
	el := buildTestSignedPropertiesElement(t, sig)

	require.Equal(t, "xades", el.Space)
	require.Equal(t, "SignedProperties", el.Tag)
	require.Equal(t, "Signature-test-SignedProperties", el.SelectAttrValue("Id", ""))

	signingTime := el.FindElement("xades:SignedSignatureProperties/xades:SigningTime")
	require.NotNil(t, signingTime)
	require.Equal(t, "2024-03-15T10:11:12Z", signingTime.Text())

	dataObjectProps := el.FindElement("xades:SignedDataObjectProperties")
	require.Nil(t, dataObjectProps)
}

func TestBuildSignedPropertiesElement_WithSignedPropertiesCustomElements(t *testing.T) {
	customElements := func() *[]*etree.Element {
		el := etree.NewElement("xades:SignedDataObjectProperties")
		el.CreateElement("xades:DataObjectFormat").CreateAttr("ObjectReference", "#Reference")
		elements := []*etree.Element{el}
		return &elements
	}

	sig := createCommonSignature()
	sig.opts.xadesOptions.SignedPropertiesCustomElements = customElements()
	el := buildTestSignedPropertiesElement(t, sig)

	dataObjectProps := el.FindElement("xades:SignedDataObjectProperties/xades:DataObjectFormat")
	require.NotNil(t, dataObjectProps)
	require.Equal(t, "#Reference", dataObjectProps.SelectAttrValue("ObjectReference", ""))
}

func TestBuildSignedPropertiesElement_WithSignedSignaturePropertiesCustomElements(t *testing.T) {
	customElements := func() *[]*etree.Element {
		role := etree.NewElement("xades:SignerRole")
		role.CreateElement("xades:ClaimedRoles").CreateElement("xades:ClaimedRole").SetText("test-role")
		elements := []*etree.Element{role}
		return &elements
	}

	sig := createCommonSignature()
	sig.opts.xadesOptions.SignedSignaturePropertiesCustomElements = customElements()
	el := buildTestSignedPropertiesElement(t, sig)

	role := el.FindElement("xades:SignedSignatureProperties/xades:SignerRole/xades:ClaimedRoles/xades:ClaimedRole")
	require.NotNil(t, role)
	require.Equal(t, "test-role", role.Text())
}

func buildTestSignedPropertiesElement(t *testing.T, sig *Signature) *etree.Element {
	cert, err := LoadCertificate(internalTestCertificateFile, internalTestCertificatePass)
	require.NoError(t, err)

	certHash := sig.opts.xadesOptions.CertificateHash
	fingerprint, err := cert.Fingerprint(certHash)
	require.NoError(t, err)
	certDigestAlgorithm, err := hashAlgorithmURI(certHash)
	require.NoError(t, err)

	el := sig.buildSignedPropertiesElement(cert, certDigestAlgorithm, fingerprint)
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
	sig.opts.xadesOptions = *normalizeXAdESOptions(&XAdESOptions{
		AttachQualifyingProperties: true,
		TimestampFormatter: func(time.Time) string {
			return fixedTime.Format(time.RFC3339)
		},
	})
	return sig
}
