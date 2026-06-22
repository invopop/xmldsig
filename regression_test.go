package xmldsig_test

import (
	"encoding/xml"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/invopop/xmldsig"
	"github.com/invopop/xmldsig/profiles/facturae"
	"github.com/invopop/xmldsig/profiles/ksef"
	"github.com/invopop/xmldsig/profiles/verifactu"
	"github.com/invopop/xmldsig/profiles/zatca"
	"github.com/stretchr/testify/require"
)

// updateGolden regenerates the golden signature files instead of asserting
// against them. Run: go test -tags unit -run TestProfileRegression -update ./...
var updateGolden = flag.Bool("update", false, "update regression golden files")

// signatureValuePattern blanks out the (non-deterministic for ECDSA) signature
// value so goldens stay stable. SignatureValue correctness is covered
// separately by TestSigningFlow_* which verifies it cryptographically.
var signatureValuePattern = regexp.MustCompile(`(?s)(<ds:SignatureValue[^>]*>).*?(</ds:SignatureValue>)`)

// TestProfileRegression locks the full signed-properties / SignedInfo output of
// each signing profile against a committed golden file, so any unintended
// change to canonicalization, digests, transforms, or serialization is caught.
//
// Inputs are fully pinned (fixed certificate, document ID and signing time) so
// every deterministic byte of the signature is reproducible.
func TestProfileRegression(t *testing.T) {
	signingTime := time.Date(2024, 3, 15, 10, 11, 12, 0, time.UTC)

	cases := []struct {
		name     string
		certFile string
		certPass string
		docFile  string
		options  func(cert *xmldsig.Certificate) []xmldsig.Option
	}{
		{
			name:     "facturae",
			certFile: "certs/facturae.p12",
			certPass: "invopop",
			docFile:  "data/invoice-vat.xml",
			options: func(cert *xmldsig.Certificate) []xmldsig.Option {
				base := xmldsig.XAdESConfig{
					Role:        xmldsig.XAdESSignerRole("third party"),
					Description: "regression test",
				}
				return []xmldsig.Option{
					xmldsig.WithXMLDSigConfig(facturae.XMLDSigConfig()),
					xmldsig.WithXAdESConfig(facturae.XAdESConfig(base)),
				}
			},
		},
		{
			name:     "verifactu",
			certFile: "certs/cert-20260102-131809.pfx",
			certPass: "",
			docFile:  "data/invoice-vat.xml",
			options: func(cert *xmldsig.Certificate) []xmldsig.Option {
				return []xmldsig.Option{
					xmldsig.WithXMLDSigConfig(verifactu.XMLDSigConfig()),
					xmldsig.WithXAdESConfig(verifactu.XAdESConfig()),
				}
			},
		},
		{
			name:     "ksef",
			certFile: "certs/cert-20260102-131809.pfx",
			certPass: "",
			docFile:  "data/ksef-auth-request.xml",
			options: func(cert *xmldsig.Certificate) []xmldsig.Option {
				return []xmldsig.Option{
					xmldsig.WithXMLDSigConfig(ksef.XMLDSigConfig()),
					xmldsig.WithXAdESConfig(ksef.XAdESConfig()),
				}
			},
		},
		{
			name:     "zatca",
			certFile: "certs/test-ec-certificate.pfx",
			certPass: "password-goes-here",
			docFile:  "data/invoice-vat.xml",
			options: func(cert *xmldsig.Certificate) []xmldsig.Option {
				return []xmldsig.Option{
					xmldsig.WithXMLDSigConfig(zatca.XMLDSigConfig()),
					xmldsig.WithXAdESConfig(zatca.XAdESConfig()),
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := xmldsig.LoadCertificate(tc.certFile, tc.certPass)
			require.NoError(t, err)

			doc, err := os.ReadFile(tc.docFile)
			require.NoError(t, err)

			opts := append(tc.options(cert),
				xmldsig.WithCertificate(cert),
				xmldsig.WithDocID("test"),
				xmldsig.WithCurrentTime(func() time.Time { return signingTime }),
			)

			signature, err := xmldsig.Sign(doc, opts...)
			require.NoError(t, err)
			require.NotEmpty(t, signature.Value.Value, "signature value should not be empty")

			marshaled, err := xml.MarshalIndent(signature, "", "  ")
			require.NoError(t, err)
			got := signatureValuePattern.ReplaceAll(marshaled, []byte("${1}SIGNATURE_VALUE${2}"))
			got = append(got, '\n')

			goldenPath := filepath.Join("data", "regression", tc.name+".xml")
			if *updateGolden {
				require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0o755))
				require.NoError(t, os.WriteFile(goldenPath, got, 0o644))
				return
			}

			want, err := os.ReadFile(goldenPath)
			require.NoError(t, err, "missing golden file; regenerate with -update")
			require.Equal(t, string(want), string(got),
				"signature output changed for profile %q; if intended, regenerate with -update", tc.name)
		})
	}
}
