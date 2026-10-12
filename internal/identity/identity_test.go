package identity

import (
	"strings"
	"testing"
)

func TestParser(t *testing.T) {
	for _, v := range []string{"spiffe://alpha.local/api-a", "spiffe://a_b/Upper.Case", "spiffe://alpha.local", "spiffe://127.0.0.1/api"} {
		i, e := Parse(v)
		if e != nil || i.String() != v {
			t.Errorf("valid %q: %v", v, e)
		}
	}
	for _, v := range []string{"", "SPIFFE://alpha.local/a", "spiffe://Alpha.local/a", "spiffe://a/a/", "spiffe://a/../a", "spiffe://a/a//b", "spiffe://a/", "spiffe://a/a%2Fb", "spiffe://a:443/a", "spiffe://u@a/a", "spiffe://a/a?x=1", "spiffe://a/a#f", "spiffe://a/a\\b", "spiffe://[::1]/a", "spiffe://a/α", "spiffe://" + strings.Repeat("a", 256) + "/a"} {
		if _, e := Parse(v); e == nil {
			t.Errorf("accepted malicious URI %q", v)
		}
	}
}
func FuzzParser(f *testing.F) {
	for _, s := range []string{"spiffe://a/b", "spiffe://a/a%2Fb", "spiffe://a/../b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		i, e := Parse(s)
		if e == nil {
			if i.String() != s || !i.Domain().Valid() {
				t.Fatal("noncanonical parsed ID")
			}
		}
	})
}
