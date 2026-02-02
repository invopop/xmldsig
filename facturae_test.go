package xmldsig

import "testing"

func TestFacturaeXMLDSigOptions(t *testing.T) {
	opts := FacturaeXMLDSigOptions()
	opts = *normalizeXMLDSigOptions(&opts)
	if !opts.IncludeKeyValue {
		t.Fatalf("expected IncludeKeyValue to be true")
	}
	if !opts.ReferenceKeyInfoInSignedInfo {
		t.Fatalf("expected ReferenceKeyInfoInSignedInfo to be true")
	}
}

func TestFacturaeXAdESOptionsIncludesPolicyRoleAndDataObject(t *testing.T) {
	cfg := &FacturaEConfig{
		Role:        XAdESSignerRole("issuer"),
		Description: "FacturaE data object",
		Policy: &XAdESPolicyConfig{
			URL:         "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf",
			Description: "Política de Firma FacturaE v3.1",
			Algorithm:   "http://www.w3.org/2000/09/xmldsig#sha1",
			Hash:        "Ohixl6upD6av8N7pEvDABhEL6hM=",
		},
	}
	opts := FacturaeXAdESOptions(cfg)
	opts = *normalizeXAdESOptions(&opts)
	if opts.TimestampFormatter == nil {
		t.Fatalf("expected TimestampFormatter to be set")
	}
	if opts.IssuerSerializer == nil {
		t.Fatalf("expected IssuerSerializer to be set")
	}
	if opts.SignedPropertiesCanonicalizer == nil {
		t.Fatalf("expected SignedPropertiesCanonicalizer to be set")
	}
	if opts.Role == nil || len(*opts.Role) != 1 || (*opts.Role)[0] != cfg.Role.String() {
		t.Fatalf("expected Role slice to be populated, got %+v", opts.Role)
	}
	if opts.PolicyIdentifier == nil {
		t.Fatalf("expected PolicyIdentifier to be set")
	}
	if opts.PolicyIdentifier.Identifier.Value != cfg.Policy.URL {
		t.Fatalf("unexpected policy identifier: %+v", opts.PolicyIdentifier.Identifier)
	}
	if opts.PolicyIdentifier.Description != cfg.Policy.Description {
		t.Fatalf("unexpected policy description: %s", opts.PolicyIdentifier.Description)
	}
	if opts.PolicyIdentifier.DigestMethodAlgorithm != cfg.Policy.Algorithm {
		t.Fatalf("unexpected policy algorithm: %s", opts.PolicyIdentifier.DigestMethodAlgorithm)
	}
	if opts.PolicyIdentifier.DigestValue != cfg.Policy.Hash {
		t.Fatalf("unexpected policy hash: %s", opts.PolicyIdentifier.DigestValue)
	}
	if opts.DataObjectFormat == nil {
		t.Fatalf("expected DataObjectFormat to be set")
	}
	if opts.DataObjectFormat.Description != cfg.Description {
		t.Fatalf("unexpected DataObjectFormat description: %s", opts.DataObjectFormat.Description)
	}
	if opts.DataObjectFormat.MimeType != "text/xml" {
		t.Fatalf("unexpected DataObjectFormat mime type: %s", opts.DataObjectFormat.MimeType)
	}
	if opts.DataObjectFormat.ObjectIdentifier == nil {
		t.Fatalf("expected DataObjectFormat.ObjectIdentifier to be set")
	}
	if opts.DataObjectFormat.ObjectIdentifier.Identifier.Qualifier != "OIDAsURN" {
		t.Fatalf("unexpected qualifier: %s", opts.DataObjectFormat.ObjectIdentifier.Identifier.Qualifier)
	}
	if opts.DataObjectFormat.ObjectIdentifier.Identifier.Value != "urn:oid:1.2.840.10003.5.109.10" {
		t.Fatalf("unexpected identifier value: %s", opts.DataObjectFormat.ObjectIdentifier.Identifier.Value)
	}
}
