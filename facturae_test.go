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
	policy := &XAdESPolicyConfig{
		URL:         "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf",
		Description: "Política de Firma FacturaE v3.1",
		Algorithm:   "http://www.w3.org/2000/09/xmldsig#sha1",
		Hash:        "Ohixl6upD6av8N7pEvDABhEL6hM=",
	}
	inputOpts := XAdESOptions{
		Role:        XAdESSignerRole("issuer"),
		Description: "FacturaE data object",
		Policy:      policy,
	}

	opts := FacturaeXAdESOptions(inputOpts)
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

	if opts.Role != inputOpts.Role {
		t.Fatalf("expected Role to be %q, got %q", inputOpts.Role, opts.Role)
	}

	if opts.Policy == nil {
		t.Fatalf("expected Policy to be set")
	}
	if opts.Policy.URL != policy.URL {
		t.Fatalf("expected Policy URL to be %s, got %s", policy.URL, opts.Policy.URL)
	}
	if opts.Policy.Description != policy.Description {
		t.Fatalf("expected Policy Description to be %s, got %s", policy.Description, opts.Policy.Description)
	}
	if opts.Policy.Algorithm != policy.Algorithm {
		t.Fatalf("expected Policy Algorithm to be %s, got %s", policy.Algorithm, opts.Policy.Algorithm)
	}
	if opts.Policy.Hash != policy.Hash {
		t.Fatalf("expected Policy Hash to be %s, got %s", policy.Hash, opts.Policy.Hash)
	}

	if opts.DataObjectFormat == nil {
		t.Fatalf("expected DataObjectFormat to be set")
	}
	if opts.DataObjectFormat.Description != inputOpts.Description {
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
