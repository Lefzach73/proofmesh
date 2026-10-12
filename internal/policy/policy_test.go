package policy

import (
	"math/rand"
	"proofmesh.local/research/internal/bundle"
	"proofmesh.local/research/internal/evidence"
	"proofmesh.local/research/internal/identity"
	"testing"
)

func fixture() (Config, Request, bundle.Store) {
	a, _ := identity.ParseDomain("alpha.local")
	i, _ := identity.Parse("spiffe://alpha.local/a")
	dst, _ := identity.Parse("spiffe://alpha.local/db")
	n := uint64(12)
	s, _ := bundle.New().Update(a, bundle.Snapshot{Domain: a, Sequence: &n, Epoch: 1, Issuers: []string{"k"}, Authenticated: true}, 0, true)
	c := Config{LocalDomain: a, FreshnessBudget: 30, Epoch: 1, Rules: []Rule{{i, dst, "read"}}}
	r := Request{Source: i, Target: dst, Audience: dst, Action: "read", KeyExchangeProfile: "classical", Credential: identity.Credential{ID: i, IssuerDomain: a, Issuer: "k", NotAfter: 1000, SignatureValid: true, AuthenticationProfile: "classical"}}
	return c, r, s
}
func TestBoundaryAndEvidence(t *testing.T) {
	c, r, s := fixture()
	for _, tc := range []struct {
		now    int64
		want   evidence.Outcome
		reason evidence.Reason
	}{{0, evidence.Accept, evidence.Authorized}, {30, evidence.Accept, evidence.Authorized}, {31, evidence.Indeterminate, evidence.StaleBundle}, {1000, evidence.Reject, evidence.Expired}, {-1, evidence.Indeterminate, evidence.UnknownState}} {
		d := Evaluate(c, r, s, tc.now)
		if d.Outcome != tc.want || d.Reason != tc.reason {
			t.Fatalf("time %d: %+v", tc.now, d)
		}
	}
	r.KeyExchangeProfile = "X25519MLKEM768"
	d := Evaluate(c, r, s, 0)
	if d.PQAuthenticated || d.VerificationMode != "simulated" || d.Outcome != evidence.Accept {
		t.Fatal(d)
	}
	c.RequirePQ = true
	if Evaluate(c, r, s, 0).Outcome != evidence.Reject {
		t.Fatal("false PQ acceptance")
	}
}

// Independent invariant: acceptance requires exact rule, ID, issuer domain, issuer membership, age and validity.
func TestRandomInvariant(t *testing.T) {
	rng := rand.New(rand.NewSource(7391))
	for n := 0; n < 5000; n++ {
		c, r, s := fixture()
		now := int64(rng.Intn(200))
		if rng.Intn(2) == 0 {
			r.Action = "write"
		}
		if rng.Intn(2) == 0 {
			r.Credential.SignatureValid = false
		}
		if rng.Intn(2) == 0 {
			r.Credential.Issuer = "foreign"
		}
		if rng.Intn(2) == 0 {
			r.Credential.NotAfter = 20
		}
		if rng.Intn(2) == 0 {
			r.Credential.IssuerDomain, _ = identity.ParseDomain("beta.local")
		}
		d := Evaluate(c, r, s, now)
		if d.Outcome == evidence.Accept && (r.Action != "read" || !r.Credential.SignatureValid || r.Credential.Issuer != "k" || r.Credential.IssuerDomain != r.Source.Domain() || now >= r.Credential.NotAfter || now > 30) {
			t.Fatalf("unsafe model accept: %+v", d)
		}
	}
}
func TestStrictAndDenyDefault(t *testing.T) {
	c, r, s := fixture()
	c.Strict = true
	if Evaluate(c, r, bundle.New(), 0).Outcome != evidence.Reject {
		t.Fatal("missing fail open")
	}
	c.Rules = nil
	if Evaluate(c, r, s, 0).Reason != evidence.PolicyDenied {
		t.Fatal("default allow")
	}
}
