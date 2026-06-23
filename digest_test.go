package xmldsig

import (
	"crypto"
	_ "crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestDigestBytes(t *testing.T) {
	// SHA-256("abc") base64-encoded.
	got, err := digestBytes([]byte("abc"), crypto.SHA256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
	if got != want {
		t.Fatalf("unexpected digest:\nwant %q\n got %q", want, got)
	}
}

func TestDigestBytesHex(t *testing.T) {
	// digestBytesHex computes base64(hex(hash)) instead of base64(hash).
	got, err := digestBytesHex([]byte("abc"), crypto.SHA256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "YmE3ODE2YmY4ZjAxY2ZlYTQxNDE0MGRlNWRhZTIyMjNiMDAzNjFhMzk2MTc3YTljYjQxMGZmNjFmMjAwMTVhZA=="
	if got != want {
		t.Fatalf("unexpected hex digest:\nwant %q\n got %q", want, got)
	}

	// The decoded payload must be the lowercase hex string of the raw hash,
	// i.e. exactly what digestBytes would hash but rendered as hex text.
	decoded, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("decoding base64: %v", err)
	}
	rawHash, err := hex.DecodeString(string(decoded))
	if err != nil {
		t.Fatalf("decoded payload is not hex: %v", err)
	}
	rawWant := "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
	if base64.StdEncoding.EncodeToString(rawHash) != rawWant {
		t.Fatalf("hex payload does not match raw hash")
	}
}

func TestDigestBytesUnavailableHash(t *testing.T) {
	// MD4 is not linked in, so both helpers should report it as unavailable.
	if _, err := digestBytes([]byte("abc"), crypto.MD4); err == nil {
		t.Fatal("expected error for unavailable hash in digestBytes")
	}
	if _, err := digestBytesHex([]byte("abc"), crypto.MD4); err == nil {
		t.Fatal("expected error for unavailable hash in digestBytesHex")
	}
}
