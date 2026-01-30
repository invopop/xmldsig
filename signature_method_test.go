package xmldsig

import (
	"crypto"
	"crypto/x509"
	"testing"
)

func TestSignatureMethodURI(t *testing.T) {
	tests := []struct {
		name      string
		hash      crypto.Hash
		keyAlg    x509.PublicKeyAlgorithm
		want      string
		wantError bool
	}{
		{"rsa224", crypto.SHA224, x509.RSA, AlgDSigRSASHA224, false},
		{"rsa256", crypto.SHA256, x509.RSA, AlgDSigRSASHA256, false},
		{"rsa384", crypto.SHA384, x509.RSA, AlgDSigRSASHA384, false},
		{"rsa512", crypto.SHA512, x509.RSA, AlgDSigRSASHA512, false},
		{"rsa512/224", crypto.SHA512_224, x509.RSA, AlgDSigRSASHA512_224, false},
		{"rsa512/256", crypto.SHA512_256, x509.RSA, AlgDSigRSASHA512_256, false},
		{"ecdsa224", crypto.SHA224, x509.ECDSA, AlgDSigECDSASHA224, false},
		{"ecdsa256", crypto.SHA256, x509.ECDSA, AlgDSigECDSASHA256, false},
		{"ecdsa384", crypto.SHA384, x509.ECDSA, AlgDSigECDSASHA384, false},
		{"ecdsa512", crypto.SHA512, x509.ECDSA, AlgDSigECDSASHA512, false},
		{"unsupported hash", crypto.SHA1, x509.RSA, "", true},
		{"unsupported key algorithm", crypto.SHA256, x509.UnknownPublicKeyAlgorithm, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := signatureMethodURI(tt.hash, tt.keyAlg)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("signatureMethodURI returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("unexpected URI: got %q want %q", got, tt.want)
			}
		})
	}
}
