package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"proofmesh.local/research/internal/jsoncheck"
)

const nativeSessionArm = "B0.native-handshake"

// Explicit lab control: stock maintained mTLS verifies at the handshake. The
// established TLS session is retained; current bundle observations do not become
// per-request authorization checks. The volatile counter is the entire effect.
type nativeSessionCounter struct {
	mu                     sync.Mutex
	value                  uint64
	handshakeVerifications atomic.Uint64
}

func nativeTrustObservation(bundles x509bundle.Source, domain spiffeid.TrustDomain) map[string]any {
	row := map[string]any{"domain": domain.String(), "observed_at": time.Now().UnixNano(), "observed_at_unit": "unix_nanoseconds", "root_certificate_sha256": []string{}, "status": "source_error", "found": nil, "scope": "current-source-observation-only"}
	b, err := bundles.GetX509BundleForTrustDomain(domain)
	if err != nil {
		row["error"] = err.Error()
		// go-spiffe v2.9.0 X509Source forwards its Set lookup error unchanged.
		// No typed missing-domain error exists; only this exact known error is
		// classified as absence. Source closure and other failures remain unknown.
		if err.Error() == fmt.Sprintf("x509bundle: no X.509 bundle for trust domain %q", domain) {
			row["status"], row["found"] = "missing_domain", false
		}
		return row
	}
	if b == nil || b.TrustDomain() != domain {
		row["error"] = "source returned no bundle or a different domain"
		return row
	}
	certs := b.X509Authorities()
	if len(certs) > 128 {
		row["error"] = "public trust observation exceeds 128-authority lab bound"
		return row
	}
	roots := make([]string, 0, len(certs))
	for _, cert := range certs {
		roots = append(roots, certificateHash(cert))
	}
	sort.Strings(roots)
	row["root_certificate_sha256"], row["found"], row["status"] = roots, true, "available"
	if len(roots) == 0 {
		row["status"] = "empty"
	}
	return row
}

func (c *nativeSessionCounter) status(bundles x509bundle.Source, peer spiffeid.ID) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]any{"event": "native-session-status", "counter": c.value, "handshake_verifications": c.handshakeVerifications.Load(), "current_trust": nativeTrustObservation(bundles, peer.TrustDomain())}
}

func serveNativeSessionConnection(ctx context.Context, raw net.Conn, fixed x509svid.Source, bundles x509bundle.Source, peer spiffeid.ID, counter *nativeSessionCounter, connection uint64, emit func(map[string]any)) {
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	start := time.Now()
	_ = raw.SetDeadline(start.Add(3 * time.Second))
	o := tlsObservation{Event: "native-session-handshake", PeerVerification: "not_reached"}
	config := observedTLSConfig(true, fixed, bundles, peer, &o)
	verify := config.VerifyPeerCertificate
	config.VerifyPeerCertificate = func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
		counter.handshakeVerifications.Add(1)
		return verify(rawCerts, chains)
	}
	tc := tls.Server(raw, config)
	err := tc.HandshakeContext(ctx)
	if err == nil {
		_, err = tc.Write([]byte("hi"))
	}
	finishObservation(&o, tc, err, start)
	emit(map[string]any{"event": "native-session-handshake", "connection_id": connection, "tls": o, "authentication_scope": "handshake-historical", "handler_executed": false, "handshake_verifications": counter.handshakeVerifications.Load()})
	if err != nil {
		return
	}
	_ = tc.SetDeadline(time.Time{})
	for request := 1; request <= 128; request++ {
		// Idle reads end at EOF or the bounded lab context. A request is one byte,
		// so there is no partially started unbounded application frame.
		var input [1]byte
		if _, err = io.ReadFull(tc, input[:]); err != nil {
			return // Failed reads and normal close never execute an effect.
		}
		counter.mu.Lock()
		before := counter.value
		row := map[string]any{"event": "native-session-request", "connection_id": connection, "request_index": request, "historical_peer_id": o.PeerID, "certificate_sha256": o.PeerCertificateSHA256, "authentication_scope": "handshake-historical", "private_key_possession_verified_at_handshake": true, "per_request_chain_validation": false, "handler_before": before, "handler_after": before, "handler_executed": false, "outcome": "REJECT", "reason": "MALFORMED_REQUEST", "current_trust": nativeTrustObservation(bundles, peer.TrustDomain())}
		row["handshake_verifications"] = counter.handshakeVerifications.Load()
		valid := input[0] == '?'
		response := "no"
		if valid {
			counter.value++
			row["handler_after"], row["handler_executed"] = counter.value, true
			row["outcome"], row["reason"] = "ACCEPT", "HANDSHAKE_AUTHORIZED_OPERATION"
			response = "ok"
		}
		counter.mu.Unlock()
		// As with the application gate, the toy effect precedes response delivery.
		// A failed response cannot undo an already executed effect.
		_ = tc.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, err = tc.Write([]byte(response))
		row["response_written"] = err == nil
		if err != nil {
			row["transport_error"] = err.Error()
		}
		emit(row)
		if err != nil || !valid {
			return
		}
	}
}

// Returns a cleanup function which cancels/joins all owned connections. The
// accept-loop WaitGroup member prevents concurrent Add from racing with Wait.
func startNativeSessionListener(ctx context.Context, listener net.Listener, fixed x509svid.Source, bundles x509bundle.Source, peer spiffeid.ID, counter *nativeSessionCounter, emit func(map[string]any)) func() {
	ctx, cancel := context.WithCancel(ctx)
	stopListener := context.AfterFunc(ctx, func() { listener.Close() })
	var sessions sync.WaitGroup
	sessions.Add(1)
	go func() {
		defer sessions.Done()
		slots := make(chan struct{}, 16)
		for connection := uint64(1); connection <= 128; connection++ {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				raw.Close()
				continue
			}
			sessions.Add(1)
			go func() {
				defer sessions.Done()
				defer func() { <-slots }()
				serveNativeSessionConnection(ctx, raw, fixed, bundles, peer, counter, connection, emit)
			}()
		}
		listener.Close() // Existing bounded sessions may finish; no further accepts.
	}()
	return func() {
		cancel()
		listener.Close()
		stopListener()
		sessions.Wait()
	}
}

func nativeSessionCommand(raw []byte, role string) (string, error) {
	if len(raw) > 4096 {
		return "", errors.New("native session command exceeds bound")
	}
	if err := jsoncheck.Check(raw); err != nil {
		return "", err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "", err
	}
	if len(fields) != 1 || fields["op"] == nil {
		return "", errors.New("native session command requires exact op field")
	}
	var op string
	if err := json.Unmarshal(fields["op"], &op); err != nil {
		return "", err
	}
	if role == "server" && op == "status" || role == "client" && (op == "connect" || op == "request" || op == "close") {
		return op, nil
	}
	return "", errors.New("unknown native session command")
}

func nativeSessionAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	if ip == nil || !(ip.IsLoopback() || ip.IsPrivate()) || err != nil || n < 1 || n > 65535 {
		return errors.New("explicit loopback/private lab IP and port required")
	}
	return nil
}

func nativeSessionTLS(socket, selected, expected, role, address string) error {
	if !strings.HasPrefix(socket, "unix:///") || role != "server" && role != "client" {
		return errors.New("explicit local Workload API socket and native server/client role required")
	}
	if err := nativeSessionAddress(address); err != nil {
		return err
	}
	own, err := spiffeid.FromString(selected)
	if err != nil || own.Path() == "" {
		return errors.New("exact native session select-id required")
	}
	peer, err := spiffeid.FromString(expected)
	if err != nil || peer.Path() == "" {
		return errors.New("exact native session peer-id required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	initial, stopInitial := context.WithTimeout(ctx, 5*time.Second)
	defer stopInitial()
	live, err := workloadapi.NewX509Source(initial, workloadapi.WithClientOptions(workloadapi.WithAddr(socket)), workloadapi.WithDefaultX509SVIDPicker(func(svids []*x509svid.SVID) *x509svid.SVID {
		for _, svid := range svids {
			if svid.ID == own {
				return svid
			}
		}
		return nil
	}))
	if err != nil {
		return err
	}
	defer live.Close()
	retained, err := live.GetX509SVID()
	if err != nil {
		return err
	}
	if err := validate(retained, live, own, time.Now()); err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	instance := hex.EncodeToString(nonce[:]) // Public correlation nonce, not a key.
	var outMu sync.Mutex
	out := json.NewEncoder(os.Stdout)
	emit := func(row map[string]any) {
		row["arm"], row["process_instance_id"], row["pq_authenticated"] = nativeSessionArm, instance, false
		outMu.Lock()
		defer outMu.Unlock()
		if out.Encode(row) != nil {
			cancel()
		}
	}
	stopInput := context.AfterFunc(ctx, func() { os.Stdin.Close() })
	defer stopInput()
	counter := &nativeSessionCounter{}
	if role == "server" {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return err
		}
		defer startNativeSessionListener(ctx, listener, source{retained}, live, peer, counter, emit)()
	}
	emit(map[string]any{"event": "ready", "role": role, "id": own.String(), "certificate_sha256": certificateHash(retained.Certificates[0]), "not_before": retained.Certificates[0].NotBefore.Unix(), "not_after": retained.Certificates[0].NotAfter.Unix(), "retained_credential": true, "counter_persistence": "volatile", "authentication_scope": "handshake-historical", "per_request_chain_validation": false, "current_trust": nativeTrustObservation(live, peer.TrustDomain()), "process_uid": os.Getuid(), "handshake_verifications": counter.handshakeVerifications.Load(), "counter": uint64(0)})
	session := &applicationSession{}
	defer session.close()
	var operation, connectionAttempt uint64
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 4096)
	for commands := 0; scanner.Scan(); commands++ {
		if commands >= 512 {
			return errors.New("native session command bound exceeded")
		}
		op, err := nativeSessionCommand(scanner.Bytes(), role)
		if err != nil {
			return err
		}
		switch op {
		case "status":
			emit(counter.status(live, peer))
		case "connect":
			connectionAttempt++
			o := session.connect(ctx, address, source{retained}, live, peer)
			o.Event = "native-session-connect"
			// Keep the client observation flat like the existing mTLS control;
			// server records retain their separate nested handshake observation.
			emit(map[string]any{"event": o.Event, "connection_attempt": connectionAttempt, "accepted": o.Accepted, "peer_verification": o.PeerVerification, "peer_id": o.PeerID, "peer_certificate_sha256": o.PeerCertificateSHA256, "peer_signature": o.PeerSignature, "tls_version": o.TLSVersion, "cipher_suite": o.CipherSuite, "did_resume": o.DidResume, "duration_ms": o.DurationMS, "error": o.Error, "authentication_scope": "handshake-historical"})
		case "request":
			operation++
			row := session.request()
			row["event"], row["operation_index"] = "native-session-response", operation
			emit(row)
		case "close":
			session.close()
			emit(map[string]any{"event": "native-session-closed"})
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return scanner.Err()
}
