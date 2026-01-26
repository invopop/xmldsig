package xmldsig

import (
	"crypto"
	"testing"
)

func TestSignatureMethodURI(t *testing.T) {
	tests := []struct {
		name      string
		hash      crypto.Hash
		want      string
		wantError bool
	}{
		{"rsa224", crypto.SHA224, AlgDSigRSASHA224, false},
		{"rsa256", crypto.SHA256, AlgDSigRSASHA256, false},
		{"rsa384", crypto.SHA384, AlgDSigRSASHA384, false},
		{"rsa512", crypto.SHA512, AlgDSigRSASHA512, false},
		{"rsa512/224", crypto.SHA512_224, AlgDSigRSASHA512_224, false},
		{"rsa512/256", crypto.SHA512_256, AlgDSigRSASHA512_256, false},
		{"unsupported hash", crypto.SHA1, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := signatureMethodURI(tt.hash)
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
