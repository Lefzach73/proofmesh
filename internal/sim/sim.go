// Package sim runs bounded, immutable event schedules without network or wall clock.
package sim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"proofmesh.local/research/internal/bundle"
	"proofmesh.local/research/internal/evidence"
	"proofmesh.local/research/internal/identity"
	"proofmesh.local/research/internal/jsoncheck"
	"proofmesh.local/research/internal/policy"
)

const MaxTime int64 = 1_000_000_000_000

type Bundle struct {
	Domain        string   `json:"domain"`
	Sequence      *uint64  `json:"sequence"`
	Epoch         uint64   `json:"epoch"`
	Issuers       []string `json:"issuers"`
	Authenticated bool     `json:"authenticated"`
}
type Credential struct {
	Name           string `json:"name"`
	ID             string `json:"id"`
	IssuerDomain   string `json:"issuer_domain"`
	Issuer         string `json:"issuer"`
	NotBefore      int64  `json:"not_before"`
	NotAfter       int64  `json:"not_after"`
	SignatureValid bool   `json:"signature_valid"`
	AuthProfile    string `json:"auth_profile"`
}
type Rule struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Action string `json:"action"`
}
type Config struct {
	LocalDomain     string   `json:"local_domain"`
	Federated       []string `json:"federated"`
	Rules           []Rule   `json:"rules"`
	FreshnessBudget int64    `json:"freshness_budget"`
	Epoch           uint64   `json:"epoch"`
	RequirePQ       bool     `json:"require_pq"`
}
type Expected struct {
	Outcome evidence.Outcome `json:"outcome"`
	Reason  evidence.Reason  `json:"reason"`
}
type Event struct {
	At               int64       `json:"at"`
	Type             string      `json:"type"`
	Domain           string      `json:"domain,omitempty"`
	Issuer           string      `json:"issuer,omitempty"`
	Bundle           *Bundle     `json:"bundle,omitempty"`
	Credential       *Credential `json:"credential,omitempty"`
	CredentialName   string      `json:"credential_name,omitempty"`
	RequestID        string      `json:"request_id,omitempty"`
	Source           string      `json:"source,omitempty"`
	Target           string      `json:"target,omitempty"`
	Audience         string      `json:"audience,omitempty"`
	Action           string      `json:"action,omitempty"`
	KEX              string      `json:"key_exchange_profile,omitempty"`
	Offset           int64       `json:"offset,omitempty"`
	Unknown          bool        `json:"unknown,omitempty"`
	Expected         *Expected   `json:"expected,omitempty"`
	OracleAuthorized *bool       `json:"oracle_authorized,omitempty"`
}
type Scenario struct {
	SchemaVersion  string       `json:"schema_version"`
	ScenarioID     string       `json:"scenario_id"`
	FamilyID       string       `json:"family_id"`
	Seed           int64        `json:"seed"`
	SyntheticOnly  bool         `json:"synthetic_only"`
	Config         Config       `json:"config"`
	InitialBundles []Bundle     `json:"initial_bundles"`
	Credentials    []Credential `json:"credentials"`
	Events         []Event      `json:"events"`
}
type Log struct {
	ScenarioID   string             `json:"scenario_id"`
	FamilyID     string             `json:"family_id"`
	Seed         int64              `json:"seed"`
	EventIndex   int                `json:"event_index"`
	At           int64              `json:"at"`
	LocalTime    int64              `json:"local_time"`
	EventType    string             `json:"event_type"`
	RequestID    string             `json:"request_id,omitempty"`
	UpdateReason evidence.Reason    `json:"update_reason,omitempty"`
	Decision     *evidence.Decision `json:"decision,omitempty"`
}

func Decode(r io.Reader) (Scenario, error) {
	var s Scenario
	raw, err := io.ReadAll(io.LimitReader(r, 4*1024*1024+1))
	if err != nil {
		return s, err
	}
	if len(raw) > 4*1024*1024 {
		return s, fmt.Errorf("scenario exceeds 4 MiB")
	}
	if err = jsoncheck.Check(raw); err != nil {
		return s, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&s); err != nil {
		return s, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return s, fmt.Errorf("trailing JSON data")
	}
	return s, Validate(s)
}
func compile(c Config) (policy.Config, error) {
	p := policy.Config{FreshnessBudget: c.FreshnessBudget, Epoch: c.Epoch, RequirePQ: c.RequirePQ}
	var err error
	p.LocalDomain, err = identity.ParseDomain(c.LocalDomain)
	if err != nil {
		return p, err
	}
	for _, v := range c.Federated {
		d, e := identity.ParseDomain(v)
		if e != nil {
			return p, e
		}
		p.Federated = append(p.Federated, d)
	}
	for _, v := range c.Rules {
		src, e := identity.Parse(v.Source)
		if e != nil || !src.Leaf() {
			return p, fmt.Errorf("invalid rule source")
		}
		dst, e := identity.Parse(v.Target)
		if e != nil || !dst.Leaf() || v.Action == "" {
			return p, fmt.Errorf("invalid rule target/action")
		}
		p.Rules = append(p.Rules, policy.Rule{Source: src, Target: dst, Action: v.Action})
	}
	return p, nil
}
func snapshot(b Bundle) (bundle.Snapshot, error) {
	d, e := identity.ParseDomain(b.Domain)
	return bundle.Snapshot{Domain: d, Sequence: b.Sequence, Epoch: b.Epoch, Issuers: b.Issuers, Authenticated: b.Authenticated}, e
}

var eventTypes = map[string]bool{"ISSUE_IDENTITY": true, "ROTATE_ISSUER": true, "PUBLISH_NEW_BUNDLE": true, "FETCH_BUNDLE": true, "DROP_BUNDLE_UPDATE": true, "REVOKE_ISSUER": true, "EXPIRE_SVID": true, "ADVANCE_CLOCK": true, "REQUEST_AUTH": true, "DENY_AUDIENCE": true, "PARTITION": true, "HEAL": true, "COMPROMISE_ISSUER": true, "REPLAY_OLD_BUNDLE": true, "REMOVE_FEDERATION": true, "CLOCK_SKEW": true}

func Validate(s Scenario) error {
	if s.SchemaVersion != "proofmesh-sim-1" || !s.SyntheticOnly || s.ScenarioID == "" || s.FamilyID == "" {
		return fmt.Errorf("invalid scenario metadata; only proofmesh-sim-1 synthetic schedules supported")
	}
	if _, e := compile(s.Config); e != nil {
		return e
	}
	if s.Config.FreshnessBudget < 0 || s.Config.FreshnessBudget > MaxTime {
		return fmt.Errorf("invalid budget")
	}
	if len(s.Events) > 10000 {
		return fmt.Errorf("event bound exceeded")
	}
	domains := map[string]bool{}
	for _, b := range s.InitialBundles {
		if _, e := snapshot(b); e != nil {
			return e
		}
		if domains[b.Domain] {
			return fmt.Errorf("duplicate initial domain")
		}
		domains[b.Domain] = true
	}
	names := map[string]bool{}
	for _, c := range s.Credentials {
		if c.Name == "" || names[c.Name] {
			return fmt.Errorf("duplicate/empty credential name")
		}
		names[c.Name] = true
	}
	last := int64(0)
	for _, e := range s.Events {
		if e.At < last || e.At > MaxTime || e.Offset < -MaxTime || e.Offset > MaxTime {
			return fmt.Errorf("invalid/unsorted virtual time")
		}
		last = e.At
		if !eventTypes[e.Type] {
			return fmt.Errorf("unknown event %q", e.Type)
		}
		switch e.Type {
		case "REQUEST_AUTH":
			if e.RequestID == "" || e.CredentialName == "" {
				return fmt.Errorf("request ID and credential required")
			}
		case "PUBLISH_NEW_BUNDLE", "ROTATE_ISSUER", "REPLAY_OLD_BUNDLE":
			if e.Bundle == nil {
				return fmt.Errorf("bundle required")
			}
			if _, err := snapshot(*e.Bundle); err != nil {
				return err
			}
		case "ISSUE_IDENTITY":
			if e.Credential == nil || e.Credential.Name == "" {
				return fmt.Errorf("credential required")
			}
		case "FETCH_BUNDLE", "PARTITION", "HEAL", "REVOKE_ISSUER", "COMPROMISE_ISSUER", "REMOVE_FEDERATION":
			if _, err := identity.ParseDomain(e.Domain); err != nil {
				return err
			}
		case "EXPIRE_SVID":
			if e.CredentialName == "" {
				return fmt.Errorf("credential name required")
			}
		}
	}
	return nil
}
func synthetic(c Credential) identity.Credential {
	id, _ := identity.Parse(c.ID)
	d, _ := identity.ParseDomain(c.IssuerDomain)
	return identity.Credential{ID: id, IssuerDomain: d, Issuer: c.Issuer, NotBefore: c.NotBefore, NotAfter: c.NotAfter, SignatureValid: c.SignatureValid, AuthenticationProfile: c.AuthProfile}
}

// Run never reads expected/oracle labels. Its input is not modified.
func Run(s Scenario, strict bool, budget *int64) ([]Log, error) {
	if err := Validate(s); err != nil {
		return nil, err
	}
	p, _ := compile(s.Config)
	p.Strict = strict
	if budget != nil {
		p.FreshnessBudget = *budget
	}
	cache := bundle.New()
	pub := map[string]Bundle{}
	creds := map[string]Credential{}
	blocked := map[string]bool{}
	removed := map[string]bool{}
	seen := map[string]bool{}
	for _, b := range s.InitialBundles {
		pub[b.Domain] = b
		snap, _ := snapshot(b)
		var reason evidence.Reason
		cache, reason = cache.Update(snap.Domain, snap, 0, true)
		if reason != evidence.Updated {
			return nil, fmt.Errorf("initial bundle: %s", reason)
		}
	}
	for _, c := range s.Credentials {
		creds[c.Name] = c
	}
	logs := []Log{}
	offset := int64(0)
	denied := map[string]bool{}
	for i, e := range s.Events {
		if e.Type == "CLOCK_SKEW" {
			offset = e.Offset
		}
		now := e.At + offset
		l := Log{ScenarioID: s.ScenarioID, FamilyID: s.FamilyID, Seed: s.Seed, EventIndex: i, At: e.At, LocalTime: now, EventType: e.Type, RequestID: e.RequestID}
		switch e.Type {
		case "PUBLISH_NEW_BUNDLE", "ROTATE_ISSUER":
			pub[e.Bundle.Domain] = *e.Bundle
		case "REVOKE_ISSUER":
			b, ok := pub[e.Domain]
			if !ok {
				return logs, fmt.Errorf("revocation without domain")
			}
			issuers := []string{}
			for _, v := range b.Issuers {
				if v != e.Issuer {
					issuers = append(issuers, v)
				}
			}
			b.Issuers = issuers
			if b.Sequence != nil {
				if *b.Sequence == ^uint64(0) {
					return logs, fmt.Errorf("sequence overflow")
				}
				n := *b.Sequence + 1
				b.Sequence = &n
			}
			pub[e.Domain] = b
		case "FETCH_BUNDLE":
			if blocked[e.Domain] {
				l.UpdateReason = evidence.Partitioned
				break
			}
			if removed[e.Domain] {
				l.UpdateReason = evidence.PolicyDenied
				break
			}
			b, ok := pub[e.Domain]
			if e.Bundle != nil {
				b = *e.Bundle
				ok = true
			}
			if !ok {
				l.UpdateReason = evidence.MissingBundle
				break
			}
			snap, err := snapshot(b)
			if err != nil {
				return logs, err
			}
			domain, _ := identity.ParseDomain(e.Domain)
			cache, l.UpdateReason = cache.Update(domain, snap, now, true)
		case "REPLAY_OLD_BUNDLE":
			domain, err := identity.ParseDomain(e.Domain)
			if err != nil {
				return logs, err
			}
			snap, _ := snapshot(*e.Bundle)
			cache, l.UpdateReason = cache.Update(domain, snap, now, false)
		case "DROP_BUNDLE_UPDATE":
			l.UpdateReason = evidence.Dropped
		case "PARTITION":
			blocked[e.Domain] = true
		case "HEAL":
			blocked[e.Domain] = false
		case "REMOVE_FEDERATION":
			removed[e.Domain] = true
			domain, _ := identity.ParseDomain(e.Domain)
			cache = cache.Remove(domain)
			f := []identity.Domain{}
			for _, v := range p.Federated {
				if v != domain {
					f = append(f, v)
				}
			}
			p.Federated = f
		case "ISSUE_IDENTITY":
			creds[e.Credential.Name] = *e.Credential
		case "EXPIRE_SVID":
			c, ok := creds[e.CredentialName]
			if !ok {
				return logs, fmt.Errorf("unknown expiry credential")
			}
			c.NotAfter = e.At
			creds[e.CredentialName] = c
		case "DENY_AUDIENCE":
			denied[e.Target] = true
		case "REQUEST_AUTH":
			c, ok := creds[e.CredentialName]
			src, _ := identity.Parse(e.Source)
			dst, _ := identity.Parse(e.Target)
			aud, _ := identity.Parse(e.Audience)
			r := policy.Request{Source: src, Target: dst, Audience: aud, Action: e.Action, RequestID: e.RequestID, KeyExchangeProfile: e.KEX, Credential: synthetic(c), Replayed: seen[e.RequestID], Unknown: e.Unknown || !ok}
			if denied[e.Target] {
				r.Audience = identity.ID{}
			}
			seen[e.RequestID] = true
			d := policy.Evaluate(p, r, cache, now)
			l.Decision = &d
		case "ADVANCE_CLOCK", "COMPROMISE_ISSUER": // compromise affects authoritative oracle, not secretly the verifier
		}
		logs = append(logs, l)
	}
	return logs, nil
}
