package xmldsig

import (
	"errors"

	"github.com/beevik/etree"
)

// Option function to be used for defining startup options
type Option func(o *options) error

// Namespaces defines special functionality for dealing with namespaces
type Namespaces map[string]string

type options struct {
	docID        string
	namespaces   Namespaces // map of namespace name to URL
	timestampURL string
	cert         *Certificate
	xaeds        XAdESSignerRole
	xaedsDesc    string // description of the XAdES role
}

// XAdESSignerRole defines the accepted signer roles
type XAdESSignerRole string

// Pre-defined XAdES Signer Roles
const (
	XAdESSupplier   XAdESSignerRole = "supplier"
	XAdESCustomer   XAdESSignerRole = "customer"
	XAdESThirdParty XAdESSignerRole = "third party"
)

// String converts the XAdES role into a string
func (r XAdESSignerRole) String() string {
	return string(r)
}

// WithCertificate expects a path to a file containing a PKCS12 (.p12 or .pfx) certificate
// file, and a password used to open it.
func WithCertificate(cert *Certificate) Option {
	return func(o *options) error {
		o.cert = cert
		return nil
	}
}

// WithDocID assigns a document ID to the signatures
func WithDocID(id string) Option {
	return func(o *options) error {
		o.docID = id
		return nil
	}
}

// WithXAdES adds the XAdES policy with the suggested role.
func WithXAdES(role XAdESSignerRole, desc string) Option {
	return func(o *options) error {
		o.xaeds = role
		o.xaedsDesc = desc
		return nil
	}
}

// WithTimestamp will add an official timestamp to the signature.
func WithTimestamp(url string) Option {
	return func(o *options) error {
		o.timestampURL = url
		return nil
	}
}

// WithNamespace is used to define all the namespaces that must be included in
// canonicalization processes. DSig requires each segment that is used in a hash
// to reference all previously defined namespaces, even if they are not used inside
// the current segment.
func WithNamespace(name, url string) Option {
	return func(o *options) error {
		if name == "" {
			return errors.New("cannot add anonymous namespace")
		}
		o.namespaces[name] = url
		return nil
	}
}

// Sign the provided data
func Sign(data []byte, opts ...Option) (*Signature, error) {
	return newSignature(data, opts...)
}

// Add will add the namespace and return a new instance of the map without
// modifying the original.
func (ns Namespaces) Add(name, url string) Namespaces {
	ns2 := make(Namespaces)
	for k, v := range ns {
		ns2[k] = v
	}
	ns2[name] = url
	return ns2
}

func (ns Namespaces) defs() []etree.Attr {
	attrs := make([]etree.Attr, 0)
	for k, v := range ns {
		attrs = append(attrs, etree.Attr{
			Space: "xmlns",
			Key:   k,
			Value: v,
		})
	}
	return attrs
}
