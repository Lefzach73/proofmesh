// Package policy contains a pure, fail-closed synthetic evidence evaluator.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"proofmesh.local/research/internal/bundle"
	"proofmesh.local/research/internal/evidence"
	"proofmesh.local/research/internal/identity"
	"slices"
)

type Rule struct {
	Source, Target identity.ID
	Action         string
}
type Config struct {
	LocalDomain     identity.Domain
	Federated       []identity.Domain
	Rules           []Rule
	FreshnessBudget int64
	Epoch           uint64
	Strict          bool
	RequirePQ       bool
}
type Request struct {
	Source, Target                        identity.ID
	Audience                              identity.ID
	Action, RequestID, KeyExchangeProfile string
	Credential                            identity.Credential
	Replayed, Unknown                     bool
}

func Evaluate(c Config, r Request, s bundle.Store, now int64) evidence.Decision {
	descriptor := struct {
		ID, Domain, Issuer, Profile string
		NB, NA                      int64
		Valid                       bool
	}{r.Credential.ID.String(), r.Credential.IssuerDomain.String(), r.Credential.Issuer, r.Credential.AuthenticationProfile, r.Credential.NotBefore, r.Credential.NotAfter, r.Credential.SignatureValid}
	raw, _ := json.Marshal(descriptor)
	hash := sha256.Sum256(raw)
	d := evidence.Decision{Assertions: []evidence.Reason{}, CredentialHash: hex.EncodeToString(hash[:]), Issuer: r.Credential.Issuer, KeyExchangeProfile: r.KeyExchangeProfile, PeerAuthenticationProfile: r.Credential.AuthenticationProfile, VerificationMode: "simulated"}
	reject := func(reason evidence.Reason) evidence.Decision {
		d.Outcome = evidence.Reject
		d.Reason = reason
		return d
	}
	unsure := func(reason evidence.Reason) evidence.Decision {
		d.Outcome = evidence.Indeterminate
		if c.Strict {
			d.Outcome = evidence.Reject
		}
		d.Reason = reason
		return d
	}
	if !r.Source.Leaf() || !r.Target.Leaf() || !r.Credential.ID.Leaf() {
		return reject(evidence.MalformedIdentity)
	}
	if r.Source != r.Credential.ID {
		return reject(evidence.IdentityMismatch)
	}
	if r.Credential.IssuerDomain != r.Source.Domain() {
		return reject(evidence.WrongDomain)
	}
	if !c.LocalDomain.Valid() || c.FreshnessBudget < 0 || now < 0 || r.Unknown {
		return unsure(evidence.UnknownState)
	}
	if r.Target.Domain() != c.LocalDomain {
		return reject(evidence.PolicyDenied)
	}
	if r.Source.Domain() != c.LocalDomain && !slices.Contains(c.Federated, r.Source.Domain()) {
		return reject(evidence.WrongDomain)
	}
	if r.Replayed {
		return reject(evidence.Replay)
	}
	if r.Credential.NotAfter <= r.Credential.NotBefore {
		return reject(evidence.Expired)
	}
	if now >= r.Credential.NotAfter {
		return reject(evidence.Expired)
	}
	if now < r.Credential.NotBefore {
		return reject(evidence.NotYetValid)
	}
	if !r.Credential.SignatureValid {
		return reject(evidence.InvalidSignature)
	}
	if r.Audience != r.Target {
		return reject(evidence.PolicyDenied)
	}
	allowed := false
	for _, rule := range c.Rules {
		if rule.Source == r.Source && rule.Target == r.Target && rule.Action == r.Action {
			allowed = true
			break
		}
	}
	if !allowed {
		return reject(evidence.PolicyDenied)
	}
	if r.Credential.AuthenticationProfile != "classical" {
		return unsure(evidence.CryptoMismatch)
	}
	if r.KeyExchangeProfile != "classical" && r.KeyExchangeProfile != "X25519MLKEM768" {
		return unsure(evidence.CryptoMismatch)
	}
	// Simulation cannot establish PQ signature authentication, even if a caller says it did.
	if c.RequirePQ {
		return reject(evidence.CryptoMismatch)
	}
	b, ok := s.Get(r.Source.Domain())
	if !ok {
		return unsure(evidence.MissingBundle)
	}
	d.BundleDomain = b.Domain.String()
	d.BundleSequence = b.Sequence
	d.BundleEpoch = b.Epoch
	d.BundleAge = now - b.FetchedAt
	if b.Sequence == nil {
		d.Assertions = append(d.Assertions, evidence.Unversioned)
	}
	if !b.Authenticated {
		return unsure(evidence.Unauthenticated)
	}
	if b.Epoch < c.Epoch {
		return unsure(evidence.EpochMismatch)
	}
	// Known empty/removal evidence remains a rejection even when its cache is stale.
	if !b.Has(r.Credential.Issuer) {
		return reject(evidence.RevokedIssuer)
	}
	if d.BundleAge < 0 {
		return unsure(evidence.UnknownState)
	}
	if d.BundleAge > c.FreshnessBudget {
		return unsure(evidence.StaleBundle)
	}
	d.Outcome = evidence.Accept
	d.Reason = evidence.Authorized
	return d
}
