package xmldsig_test

import (
	"testing"

	"github.com/invopop/xmldsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testCertificateFile = "./certs/facturae.p12"
	testCertificatePass = "invopop"
)

func TestCertificateLoader(t *testing.T) {
	certificate, err := xmldsig.LoadCertificate(testCertificateFile, testCertificatePass)
	require.NoError(t, err)

	t.Run("should return an error if private key is missing", func(t *testing.T) {
		_, err := xmldsig.LoadCertificate("./certs/client-without-key.p12", "invopop")
		assert.Error(t, err)
	})

	t.Run("should sign a string", func(t *testing.T) {
		signature, _ := certificate.Sign("some data to sign")
		assert.Equal(t, "Gptu4mP8yyDRAL1zRDm3qabxaqwlGspdZvXNrN6jyMgPsqCBS2coOntOiNGEWHpWNoLLjSrbeq8bqEZ0DH7xEy6MOJrbp615q6XWl4mNFXHfvQmzvp2Uo4qXiXQlFKHZ7T5lxBZmD/4Bw1SRjFpMexu6hzd9cAny/bTghiXOUn81iStM2SYuJnoRL/K5hNEIjuHB8vmtaP6y/PxC+R27Ue6JAGUfhF+Yduum3sHoJUhbWNMojGiZAtNR+n9GKbqq+SSF2SGjXQPzZeJyJ9kDRmdrLMCpwuEVGYbRTImLKWgqqKaMUQr7hoFZCmG3tObgO35TYZ6wIumJE8k149d2LQ==", signature)
	})

	t.Run("should return the certificate fingerprint", func(t *testing.T) {
		fingerprint := certificate.Fingerprint()
		assert.Equal(t, "VmNYwDiCBBXJX/IL1AUYj7uHouM2Jcp3ZkeqmB+FKGTTwXIIZnCWmZVhCSB7uNoV6Xee7nZVkMqeCMQk3tGR0g==", fingerprint)
	})

	t.Run("should return the PEM encoded certificate", func(t *testing.T) {
		pem := certificate.ToPEM()
		assert.Equal(t, "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", pem)
	})
}

func TestCertificateData(t *testing.T) {
	certificate, err := xmldsig.LoadCertificate(testCertificateFile, testCertificatePass)
	require.NoError(t, err)

	t.Run("should return the certificate issuer", func(t *testing.T) {
		issuer := certificate.Issuer()
		assert.Equal(t, "CN=AC FNMT Usuarios,OU=Ceres,O=FNMT-RCM,C=ES", issuer)
	})

	t.Run("should return the certificate serial number", func(t *testing.T) {
		serialNumber := certificate.SerialNumber()
		assert.Equal(t, "96891622000445695554354105786026700712", serialNumber)
	})

	t.Run("should return the certificate serial number", func(t *testing.T) {
		serialNumber := certificate.SerialNumber()

		assert.Equal(t, "96891622000445695554354105786026700712", serialNumber)
	})

	t.Run("should return the certificate private key info", func(t *testing.T) {
		privateKeyInfo := certificate.PrivateKeyInfo()

		assert.Equal(t, "ujAnB2L5X2Bm42S5f/axKFu1QsAcZGJAeYELZZJ04jriBu3E8V3Rus3tUxfQ+ylqBm0bNWgHfP+gekosHaYoJNQmAVBuwpd183uHksTRUtbeOAFS2xd7v29stM7ARkec+WVV+SK8G6HECIB0VIAMoB2tVs0y6XRVRcjE4I7kH1h3ZbMIzvW43B4hxruYtXcvozGwvZpxQKVrjEY8IXH5+aXHM8WLCba4I06FyhvI+2/9WUPN2YvDoml7lQM4edgepTEZifq2ZPHGpCC5NhSXj2ab5FtnGTMgUaWH6tCljT0kOdfJBOHnIWOw4dBdgkik2CuxwGyMrq/P5VqQIC2hXQ==", privateKeyInfo.Modulus)
		assert.Equal(t, "AQAB", privateKeyInfo.Exponent)
	})
}
