// Package identity provides validated, comparable SPIFFE namespace values.
package identity

import (
	"fmt"
	"strings"
)

type Domain struct{ name string }

func ParseDomain(s string) (Domain, error) {
	if len(s) == 0 || len(s) > 255 {
		return Domain{}, fmt.Errorf("invalid trust-domain length")
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return Domain{}, fmt.Errorf("invalid trust-domain character")
		}
	}
	return Domain{s}, nil
}
func (d Domain) String() string { return d.name }
func (d Domain) Valid() bool    { return d.name != "" }

type ID struct {
	domain Domain
	path   string
}

// Strict canonical parsing is deliberate: reject aliases rather than normalize policy inputs.
func Parse(s string) (ID, error) {
	if len(s) > 2048 || !strings.HasPrefix(s, "spiffe://") {
		return ID{}, fmt.Errorf("invalid SPIFFE URI")
	}
	rest := strings.TrimPrefix(s, "spiffe://")
	host, path, _ := strings.Cut(rest, "/")
	d, err := ParseDomain(host)
	if err != nil {
		return ID{}, err
	}
	if strings.Contains(rest, "/") {
		if path == "" {
			return ID{}, fmt.Errorf("empty/trailing path")
		}
		for _, seg := range strings.Split(path, "/") {
			if seg == "" || seg == "." || seg == ".." {
				return ID{}, fmt.Errorf("relative or empty segment")
			}
			for _, c := range seg {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
					return ID{}, fmt.Errorf("invalid path character")
				}
			}
		}
		path = "/" + path
	}
	return ID{d, path}, nil
}
func (i ID) Domain() Domain { return i.domain }
func (i ID) String() string {
	if !i.domain.Valid() {
		return ""
	}
	return "spiffe://" + i.domain.name + i.path
}
func (i ID) Leaf() bool { return i.domain.Valid() && i.path != "" }

// Credential is a synthetic descriptor. It is never a certificate verification result.
type Credential struct {
	ID                    ID
	IssuerDomain          Domain
	Issuer                string
	NotBefore, NotAfter   int64
	SignatureValid        bool
	AuthenticationProfile string
}
