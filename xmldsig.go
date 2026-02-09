// Package xmldsig helps generate XML files with digital signatures.
package xmldsig

import (
	"errors"
	"time"

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
	xmlOptions   XMLDSigOptions
	xadesOptions *XAdESConfig
	timeNow      func() time.Time
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

// WithTimestamp will add an official timestamp to the signature.
func WithTimestamp(url string) Option {
	return func(o *options) error {
		o.timestampURL = url
		return nil
	}
}

// WithXMLDSigOptions allows passing custom options overriding default XMLDSig settings.
func WithXMLDSigOptions(opts XMLDSigOptions) Option {
	return func(o *options) error {
		o.xmlOptions = opts
		return nil
	}
}

// WithXAdES enables XAdES support, and allows passing options overriding default XAdES settings.
// Note that unlike other options, this one accepts a pointer to XAdESConfig - this is for backward compatibility.
func WithXAdES(opts *XAdESConfig) Option {
	return func(o *options) error {
		o.xadesOptions = normalizeXAdESOptions(opts)
		return nil
	}
}

// WithCurrentTime allows a callback to be provided in order to using a
// different signing time method. This is especially useful for testing.
// Default is to provide `time.Now().UTC()`.
func WithCurrentTime(fn func() time.Time) Option {
	return func(o *options) error {
		o.timeNow = fn
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
		if k == "" {
			attrs = append(attrs, etree.Attr{
				Space: "",
				Key:   "xmlns",
				Value: v,
			})
		} else {
			attrs = append(attrs, etree.Attr{
				Space: "xmlns",
				Key:   k,
				Value: v,
			})
		}
	}
	return attrs
}
