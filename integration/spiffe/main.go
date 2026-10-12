// Disposable conventional PKI + supported go-spiffe validation/mTLS laboratory.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type source struct{ value *x509svid.SVID }

func (s source) GetX509SVID() (*x509svid.SVID, error) { return s.value, nil }

type authority struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	domain spiffeid.TrustDomain
}

func newAuthority(domain string) (authority, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return authority{}, e
	}
	id, e := spiffeid.TrustDomainFromString(domain)
	if e != nil {
		return authority{}, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return authority{}, e
	}
	uri, e := url.Parse("spiffe://" + domain)
	if e != nil {
		return authority{}, e
	}
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ProofMesh disposable lab CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, URIs: []*url.URL{uri}}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if e != nil {
		return authority{}, e
	}
	cert, e := x509.ParseCertificate(der)
	return authority{cert, key, id}, e
}
func (a authority) issue(uri string, expiry time.Time) (*x509svid.SVID, error) {
	id, e := spiffeid.FromString(uri)
	if e != nil {
		return nil, e
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, e
	}
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ProofMesh disposable workload"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, IsCA: false, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{id.URL()}}
	der, e := x509.CreateCertificate(rand.Reader, tpl, a.cert, &key.PublicKey, a.key)
	if e != nil {
		return nil, e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	return x509svid.ParseRaw(der, pk)
}
func (a authority) bundle() *x509bundle.Bundle {
	return x509bundle.FromX509Authorities(a.domain, []*x509.Certificate{a.cert})
}
func validate(svid *x509svid.SVID, bundles x509bundle.Source, allowed spiffeid.ID, now time.Time) error {
	id, _, e := x509svid.Verify(svid.Certificates, bundles, x509svid.WithTime(now))
	if e != nil {
		return e
	}
	if id.Path() == "" || id != allowed {
		return errors.New("exact peer identity policy denied")
	}
	leaf := svid.Certificates[0]
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("missing digitalSignature usage")
	}
	client, server := false, false
	for _, eku := range leaf.ExtKeyUsage {
		client = client || eku == x509.ExtKeyUsageClientAuth
		server = server || eku == x509.ExtKeyUsageServerAuth
	}
	if len(leaf.ExtKeyUsage) > 0 && (!client || !server) {
		return errors.New("SVID must support client and server authentication")
	}
	return nil
}
func exchange(server, client *x509svid.SVID, bundles *x509bundle.Set, allowedClient spiffeid.ID) error {
	sc := tlsconfig.MTLSServerConfig(source{server}, bundles, tlsconfig.AuthorizeID(allowedClient))
	sc.MinVersion = tls.VersionTLS13
	lc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer lc.Close()
	done := make(chan error, 1)
	go func() {
		c, e := lc.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		tc := tls.Server(c, sc)
		if e = tc.Handshake(); e == nil {
			_, e = tc.Write([]byte("ok"))
		}
		done <- e
	}()
	cc := tlsconfig.MTLSClientConfig(source{client}, bundles, tlsconfig.AuthorizeID(server.ID))
	cc.MinVersion = tls.VersionTLS13
	raw, e := net.DialTimeout("tcp", lc.Addr().String(), 3*time.Second)
	if e != nil {
		return e
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	tc := tls.Client(raw, cc)
	e = tc.Handshake()
	if e == nil {
		buf := make([]byte, 2)
		n, re := tc.Read(buf)
		if re != nil {
			e = re
		} else if n != 2 || string(buf) != "ok" {
			e = errors.New("unexpected response")
		}
	}
	serverErr := <-done
	if e != nil {
		return e
	}
	return serverErr
}
func lab() ([]map[string]any, error) {
	alpha, e := newAuthority("alpha.local")
	if e != nil {
		return nil, e
	}
	beta, e := newAuthority("beta.local")
	if e != nil {
		return nil, e
	}
	a, e := alpha.issue("spiffe://alpha.local/db", time.Now().Add(10*time.Minute))
	if e != nil {
		return nil, e
	}
	b, e := beta.issue("spiffe://beta.local/api-b", time.Now().Add(10*time.Minute))
	if e != nil {
		return nil, e
	}
	forged, e := beta.issue("spiffe://alpha.local/db", time.Now().Add(10*time.Minute))
	if e != nil {
		return nil, e
	}
	expired, e := beta.issue("spiffe://beta.local/api-b", time.Now().Add(-time.Second))
	if e != nil {
		return nil, e
	}
	set := x509bundle.NewSet(alpha.bundle(), beta.bundle())
	cases := []struct {
		name   string
		result error
		want   bool
	}{{"valid-beta-chain", validate(b, set, b.ID, time.Now()), true}, {"foreign-issuer-claiming-alpha", validate(forged, set, a.ID, time.Now()), false}, {"expired-svid", validate(expired, set, b.ID, time.Now()), false}, {"unauthorized-exact-peer", validate(b, set, a.ID, time.Now()), false}, {"missing-domain-bundle", validate(b, x509bundle.NewSet(alpha.bundle()), b.ID, time.Now()), false}, {"cross-domain-mtls", exchange(a, b, set, b.ID), true}, {"mtls-denied-peer", exchange(a, b, set, a.ID), false}}
	records := []map[string]any{}
	for _, c := range cases {
		ok := c.result == nil
		record := map[string]any{"case": c.name, "accepted": ok, "expected_accepted": c.want, "passed": ok == c.want, "verification_mode": "go-spiffe-real-x509", "authentication_profile": "ECDSA-P256", "pq_authenticated": false}
		if c.result != nil {
			record["error"] = c.result.Error()
		}
		h := sha256.Sum256(b.Certificates[0].Raw)
		record["example_certificate_sha256"] = hex.EncodeToString(h[:])
		records = append(records, record)
		if ok != c.want {
			e = fmt.Errorf("lab mismatch: %s", c.name)
		}
	}
	return records, e
}
func workload(socket string) error { return inspectWorkload(socket, "", "", "", false) }
func inspectWorkload(socket, peerFile, expectedPeer, selectID string, exportPublic bool) error {
	if !strings.HasPrefix(socket, "unix:///") {
		return errors.New("only explicit local unix:/// Workload API sockets supported")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, e := workloadapi.New(ctx, workloadapi.WithAddr(socket))
	if e != nil {
		return e
	}
	defer client.Close()
	xc, e := client.FetchX509Context(ctx)
	if e != nil {
		return e
	}
	if len(xc.SVIDs) == 0 {
		return errors.New("no SVID issued")
	}
	s := xc.SVIDs[0]
	if selectID != "" {
		s = nil
		for _, candidate := range xc.SVIDs {
			if candidate.ID.String() == selectID {
				s = candidate
				break
			}
		}
		if s == nil {
			return errors.New("selected SPIFFE ID not present in issued context")
		}
	}
	if peerFile != "" {
		expected, e := spiffeid.FromString(expectedPeer)
		if e != nil {
			return e
		}
		file, e := os.Open(peerFile)
		if e != nil {
			return e
		}
		raw, e := io.ReadAll(io.LimitReader(file, 1024*1024+1))
		file.Close()
		if e != nil {
			return e
		}
		if len(raw) > 1024*1024 {
			return errors.New("peer certificate input exceeds bound")
		}
		certs := []*x509.Certificate{}
		for len(raw) > 0 {
			block, rest := pem.Decode(raw)
			if block == nil {
				break
			}
			raw = rest
			if block.Type != "CERTIFICATE" {
				return errors.New("only public certificates permitted")
			}
			cert, e := x509.ParseCertificate(block.Bytes)
			if e != nil {
				return e
			}
			certs = append(certs, cert)
		}
		if len(certs) == 0 || len(certs) > 10 {
			return errors.New("invalid peer chain size")
		}
		id, e := x509svid.IDFromCert(certs[0])
		if e != nil {
			return e
		}
		peer := &x509svid.SVID{ID: id, Certificates: certs}
		if e = validate(peer, xc.Bundles, expected, time.Now()); e != nil {
			return e
		}
		hash := sha256.Sum256(certs[0].Raw)
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"peer_id": id.String(), "certificate_sha256": hex.EncodeToString(hash[:]), "cryptographically_validated": true, "pq_authenticated": false, "validation_source": "live-workload-api-bundles"})
	}
	if e = validate(s, xc.Bundles, s.ID, time.Now()); e != nil {
		return e
	}
	if exportPublic {
		for _, cert := range s.Certificates {
			if e = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); e != nil {
				return e
			}
		}
		return nil
	}
	trusted := map[string][]string{}
	for _, b := range xc.Bundles.Bundles() {
		keys := []string{}
		for _, a := range b.X509Authorities() {
			h := sha256.Sum256(a.Raw)
			keys = append(keys, hex.EncodeToString(h[:]))
		}
		trusted[b.TrustDomain().String()] = keys
	}
	hash := sha256.Sum256(s.Certificates[0].Raw)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"id": s.ID.String(), "certificate_sha256": hex.EncodeToString(hash[:]), "signature_algorithm": s.Certificates[0].SignatureAlgorithm.String(), "cryptographically_validated": true, "pq_authenticated": false, "source": "local-workload-api", "trusted_bundles": trusted})
}
func main() {
	socket := flag.String("workload-socket", "", "optional local Workload API socket")
	peer := flag.String("peer-cert", "", "public peer certificate chain PEM")
	expected := flag.String("peer-id", "", "exact authorized peer identity")
	selected := flag.String("select-id", "", "issued identity to select")
	export := flag.Bool("export-public-cert", false, "emit only public certificate chain, never keys")
	mtlsRole := flag.String("mtls-role", "", "bounded live lab mode: server or client")
	mtlsAddress := flag.String("mtls-address", "", "internal lab listen/dial address")
	nativeSessionRole := flag.String("native-session-role", "", "opt-in B0.native-handshake retained-session lab: server or client")
	nativeSessionAddr := flag.String("native-session-address", "", "explicit loopback/private lab IP:port for retained native session")
	bundleEndpoint := flag.String("paired-bundle-endpoint", "", "opt-in paired chain-validation lab: authenticated https_spiffe endpoint")
	endpointID := flag.String("bundle-endpoint-id", "", "exact SPIFFE ID authorizing the bundle endpoint")
	appRole := flag.String("application-role", "", "bounded application-gate lab: server or client")
	appAddress := flag.String("application-address", "", "base server port (three arms) or client address")
	appAllowed := flag.String("application-allowed-peers", "", "server exact peer IDs separated by commas")
	appBudget := flag.Int("application-budget", 3, "fixed common B2/B3 budget (0, 3, 120 seconds)")
	appState := flag.String("application-state", "", "opt-in absolute durable public-trust checkpoint (server only)")
	appProtocol := flag.String("application-protocol", "fixed-v1", "fixed-v1 or opt-in durable request-v1")
	appCrash := flag.Bool("application-test-crash", false, "enable explicit self-SIGKILL on local lab control pipe; requires durable server mode")
	publisherAddress := flag.String("publisher-address", "", "opt-in controlled public-bundle publisher on an internal lab IP:port")
	flag.Parse()
	if *nativeSessionAddr != "" && *nativeSessionRole == "" {
		fmt.Fprintln(os.Stderr, "native-session-address requires native-session-role")
		os.Exit(1)
	}
	if *nativeSessionRole != "" {
		if *publisherAddress != "" || *appRole != "" || *mtlsRole != "" || *bundleEndpoint != "" || *appState != "" || *appCrash || *peer != "" || *export {
			fmt.Fprintln(os.Stderr, "native-session mode must be selected alone")
			os.Exit(1)
		}
		if e := nativeSessionTLS(*socket, *selected, *expected, *nativeSessionRole, *nativeSessionAddr); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if *publisherAddress != "" {
		if e := publisherLab(*socket, *selected, *publisherAddress); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if *appRole != "" {
		if *appState != "" && *appRole != "server" {
			fmt.Fprintln(os.Stderr, "application-state requires server role")
			os.Exit(1)
		}
		if *appCrash && (*appState == "" || *appRole != "server") {
			fmt.Fprintln(os.Stderr, "test crash requires durable server mode")
			os.Exit(1)
		}
		if e := applicationTLS(*socket, *selected, *expected, *appRole, *appAddress, *appAllowed, *bundleEndpoint, *endpointID, *appState, *appProtocol, *appBudget, *appCrash); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if *bundleEndpoint != "" {
		if e := pairedBundleLab(*socket, *selected, *expected, *bundleEndpoint, *endpointID); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if *mtlsRole != "" {
		if e := liveTLS(*socket, *selected, *expected, *mtlsRole, *mtlsAddress); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if *socket != "" {
		if e := inspectWorkload(*socket, *peer, *expected, *selected, *export); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	records, e := lab()
	_ = json.NewEncoder(os.Stdout).Encode(records)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
