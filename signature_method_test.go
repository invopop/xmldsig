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
		{"rsa256", crypto.SHA256, AlgDSigRSASHA256, false},
		{"rsa512", crypto.SHA512, AlgDSigRSASHA512, false},
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
