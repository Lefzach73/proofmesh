// Authenticated federation-bundle fetches and paired REAL chain validation.
// This is a configured direct-fetch reference, not the native SPIRE federation
// cache and not TLS proof of private-key possession. The mTLS lab is separate.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	corebundle "proofmesh.local/research/internal/bundle"
	"proofmesh.local/research/internal/evidence"
	coreid "proofmesh.local/research/internal/identity"
	"proofmesh.local/research/internal/jsoncheck"
	"proofmesh.local/research/internal/policy"
)

type authenticatedBundle struct {
	bundle     *spiffebundle.Bundle
	started    time.Time
	bodySHA256 string
}

func fetchAuthenticatedBundle(ctx context.Context, endpoint string, endpointID spiffeid.ID, trust x509bundle.Source) (authenticatedBundle, error) {
	var empty authenticatedBundle
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || endpointID.Path() == "" {
		return empty, errors.New("explicit https_spiffe endpoint and exact endpoint ID required")
	}
	config := tlsconfig.TLSClientConfig(trust, tlsconfig.AuthorizeID(endpointID))
	config.MinVersion = tls.VersionTLS13
	config.CurvePreferences = []tls.CurveID{tls.X25519}
	config.SessionTicketsDisabled = true
	transport := &http.Transport{TLSClientConfig: config, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("lab endpoint redirects disabled") }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return empty, err
	}
	request.Header.Set("Accept", "application/json")
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return empty, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return empty, fmt.Errorf("bundle endpoint HTTP status %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil {
		return empty, err
	}
	if len(raw) > 1024*1024 {
		return empty, errors.New("bundle response exceeds 1 MiB")
	}
	if err = checkBundleJSON(raw); err != nil {
		return empty, err
	}
	b, err := spiffebundle.Parse(endpointID.TrustDomain(), raw)
	if err != nil {
		return empty, err
	}
	// An authenticated empty array removes previously published authorities.
	h := sha256.Sum256(raw)
	return authenticatedBundle{b, started, hex.EncodeToString(h[:])}, nil
}

type pairedCache struct {
	remote   spiffeid.TrustDomain
	bundle   *spiffebundle.Bundle
	store    corebundle.Store
	fetched  time.Time
	bodyHash string
}

func (c *pairedCache) trustForFetch(bootstrap x509bundle.Source) x509bundle.Source {
	if c.bundle != nil {
		// Never re-enable an authority removed by a direct update merely because
		// the Workload API bootstrap view has not received that removal yet.
		return c.bundle.X509Bundle()
	}
	for _, record := range c.store.Records() {
		if record.Domain == c.remote.String() {
			// A known removal is not a new cache eligible for bootstrap trust.
			return x509bundle.New(c.remote)
		}
	}
	return bootstrap
}

func (c *pairedCache) apply(response authenticatedBundle) (evidence.Reason, error) {
	if response.bundle.TrustDomain() != c.remote {
		return evidence.WrongDomain, errors.New("endpoint domain binding mismatch")
	}
	d, err := coreid.ParseDomain(c.remote.String())
	if err != nil {
		return evidence.WrongDomain, err
	}
	var sequence *uint64
	if n, ok := response.bundle.SequenceNumber(); ok {
		sequence = &n
	}
	keys := []string{}
	for _, cert := range response.bundle.X509Authorities() {
		keys = append(keys, certificateHash(cert))
	}
	next, reason := c.store.Update(d, corebundle.Snapshot{Domain: d, Sequence: sequence, Epoch: 1, Issuers: keys, Authenticated: true}, response.started.Unix(), true)
	if reason != evidence.Updated {
		return reason, nil
	}
	// ALL arms share this single admitted snapshot. The stock-reference arm is
	// not intentionally weakened to ignore a rejected metadata update.
	c.store = next
	c.bundle = response.bundle.Clone()
	c.fetched = response.started
	c.bodyHash = response.bodySHA256
	return reason, nil
}

func (c *pairedCache) summary() map[string]any {
	d, _ := coreid.ParseDomain(c.remote.String())
	snapshot, ok := c.store.Get(d)
	var hint *float64
	if c.bundle != nil {
		if duration, ok := c.bundle.RefreshHint(); ok {
			seconds := duration.Seconds()
			hint = &seconds
		}
	}
	return map[string]any{"has_bundle": ok, "domain": c.remote.String(), "sequence": snapshot.Sequence, "refresh_hint_seconds": hint, "root_certificate_sha256": snapshot.Issuers, "fetched_at": snapshot.FetchedAt, "response_sha256": c.bodyHash, "age_basis": "start of successfully authenticated direct HTTPS fetch; not authoritative publication time"}
}

func readPublicChain(path string) ([]*x509.Certificate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 1024*1024 {
		return nil, errors.New("peer chain exceeds 1 MiB")
	}
	certs := []*x509.Certificate{}
	for len(bytes.TrimSpace(raw)) > 0 {
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("only public certificate PEM blocks allowed")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		raw = rest
		if len(certs) > 10 {
			return nil, errors.New("peer chain exceeds certificate bound")
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("empty peer certificate chain")
	}
	return certs, nil
}

func (c *pairedCache) check(certs []*x509.Certificate, ownID, expected spiffeid.ID, now time.Time) map[string]any {
	result := map[string]any{"event": "paired-check", "snapshot": c.summary(), "certificate_sha256": certificateHash(certs[0]), "signature_algorithm": certs[0].SignatureAlgorithm.String(), "pq_authenticated": false, "private_key_possession_tested": false, "scope": "real chain verification plus core metadata policy; mTLS possession is tested separately", "checked_at": now.Unix()}
	decisions := map[string]any{}
	result["decisions"] = decisions
	if c.bundle == nil {
		result["error"] = "no admitted authenticated bundle"
		result["eligible"] = false
		return result
	}
	id, chains, err := x509svid.Verify(certs, c.bundle.X509Bundle(), x509svid.WithTime(now))
	if err == nil && (id != expected || id.Path() == "") {
		err = errPeerPolicy
	}
	if err == nil {
		// Keep exact identity, digitalSignature and EKU checks identical to the
		// existing real adapter. Verify also supplies the actual verified root
		// used to project issuer membership into the metadata evaluator.
		err = validate(&x509svid.SVID{ID: id, Certificates: certs}, c.bundle.X509Bundle(), expected, now)
	}
	result["cryptographically_validated"] = err == nil
	result["verification_result"] = verificationOutcome(err)
	result["eligible"] = true
	if err != nil {
		result["verification_error"] = err.Error()
		for _, arm := range []string{"B0.direct", "B2/0", "B3/0", "B2/3", "B3/3", "B2/120", "B3/120"} {
			decisions[arm] = map[string]any{"outcome": "REJECT", "reason": "REAL_CHAIN_OR_EXACT_PEER_REJECTED", "verification_mode": "go-spiffe-real-x509"}
		}
		return result
	}
	decisions["B0.direct"] = map[string]any{"outcome": "ACCEPT", "reason": "REAL_CHAIN_AND_EXACT_PEER_VALID", "verification_mode": "go-spiffe-real-x509"}
	peer, _ := coreid.Parse(id.String())
	local, _ := coreid.Parse(ownID.String())
	domain, _ := coreid.ParseDomain(c.remote.String())
	issuer := certificateHash(chains[0][len(chains[0])-1])
	request := policy.Request{Source: peer, Target: local, Audience: local, Action: "connect", KeyExchangeProfile: "classical", Credential: coreid.Credential{ID: peer, IssuerDomain: domain, Issuer: issuer, NotBefore: certs[0].NotBefore.Unix(), NotAfter: certs[0].NotAfter.Unix(), SignatureValid: true, AuthenticationProfile: "classical"}}
	for _, budget := range []int64{0, 3, 120} {
		for _, strict := range []bool{true, false} {
			config := policy.Config{LocalDomain: local.Domain(), Federated: []coreid.Domain{domain}, FreshnessBudget: budget, Epoch: 1, Strict: strict, Rules: []policy.Rule{{Source: peer, Target: local, Action: "connect"}}}
			arm := "B3"
			if strict {
				arm = "B2"
			}
			// Preserve the core's "simulated" metadata-evaluator label. The outer
			// record is the separate, actually executed cryptographic verification.
			decisions[fmt.Sprintf("%s/%d", arm, budget)] = policy.Evaluate(config, request, c.store, now.Unix())
		}
	}
	return result
}

type pairedCommand struct {
	Op           string `json:"op"`
	Certificate  string `json:"certificate,omitempty"`
	ExpectedPeer string `json:"expected_peer,omitempty"`
}

func pairedBundleLab(socket, selected, expectedPeer, endpoint, endpointName string) error {
	if !strings.HasPrefix(socket, "unix:///") {
		return errors.New("explicit local Workload API socket required")
	}
	own, err := spiffeid.FromString(selected)
	if err != nil || own.Path() == "" {
		return errors.New("exact workload identity required")
	}
	peer, err := spiffeid.FromString(expectedPeer)
	if err != nil || peer.Path() == "" {
		return errors.New("exact peer identity required")
	}
	endpointID, err := spiffeid.FromString(endpointName)
	if err != nil || endpointID.TrustDomain() != peer.TrustDomain() {
		return errors.New("endpoint identity must bind expected peer domain")
	}
	initCtx, initCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer initCancel()
	live, err := workloadapi.NewX509Source(initCtx, workloadapi.WithClientOptions(workloadapi.WithAddr(socket)))
	if err != nil {
		return err
	}
	defer live.Close()
	// The local Workload API supplies bootstrap trust only. Subsequent fetches
	// authenticate the endpoint against the last admitted direct bundle.
	cache := pairedCache{remote: peer.TrustDomain(), store: corebundle.New()}
	out := json.NewEncoder(os.Stdout)
	refresh := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		response, err := fetchAuthenticatedBundle(ctx, endpoint, endpointID, cache.trustForFetch(live))
		row := map[string]any{"event": "refresh", "success": false}
		if err != nil {
			row["error"] = err.Error()
		} else {
			reason, applyErr := cache.apply(response)
			row["update_reason"] = reason
			row["success"] = applyErr == nil && reason == evidence.Updated
			if applyErr != nil {
				row["error"] = applyErr.Error()
			}
		}
		row["snapshot"] = cache.summary()
		return out.Encode(row)
	}
	if err := out.Encode(map[string]any{"event": "ready", "scope": "paired direct-fetch chain lab; no private-key export", "pq_authenticated": false}); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { os.Stdin.Close() })
	defer stop()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 4096)
	for n := 0; scanner.Scan(); n++ {
		if n >= 512 {
			return errors.New("paired command bound exceeded")
		}
		if err := jsoncheck.Check([]byte(scanner.Text())); err != nil {
			return err
		}
		var command pairedCommand
		decoder := json.NewDecoder(strings.NewReader(scanner.Text()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&command); err != nil {
			return err
		}
		if decoder.Decode(new(any)) != io.EOF {
			return errors.New("trailing command")
		}
		switch command.Op {
		case "refresh":
			if err := refresh(); err != nil {
				return err
			}
		case "check":
			expected := peer
			if command.ExpectedPeer != "" {
				var err error
				expected, err = spiffeid.FromString(command.ExpectedPeer)
				if err != nil {
					return err
				}
			}
			certs, err := readPublicChain(command.Certificate)
			if err != nil {
				return err
			}
			if err := out.Encode(cache.check(certs, own, expected, time.Now())); err != nil {
				return err
			}
		default:
			return errors.New("unknown paired operation")
		}
	}
	return scanner.Err()
}
