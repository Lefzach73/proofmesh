package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

var errPeerPolicy = errors.New("exact peer identity policy denied")

// Only public metadata is serialized. A retained SVID's private key stays in this
// process, permitting new handshakes with the SAME old credential after rotation.
type tlsObservation struct {
	Event                 string  `json:"event"`
	Accepted              bool    `json:"accepted"`
	PeerVerification      string  `json:"peer_verification"`
	PeerID                string  `json:"peer_id,omitempty"`
	PeerCertificateSHA256 string  `json:"peer_certificate_sha256,omitempty"`
	PeerSignature         string  `json:"peer_signature,omitempty"`
	TLSVersion            uint16  `json:"tls_version,omitempty"`
	CipherSuite           string  `json:"cipher_suite,omitempty"`
	DidResume             bool    `json:"did_resume"`
	PQAuthenticated       bool    `json:"pq_authenticated"`
	DurationMS            float64 `json:"duration_ms"`
	Error                 string  `json:"error,omitempty"`
}

func certificateHash(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(h[:])
}

func verificationOutcome(err error) string {
	if err == nil {
		return "verified"
	}
	if errors.Is(err, errPeerPolicy) {
		return "peer_policy_denied"
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return "unknown_authority"
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return "certificate_expired"
	}
	return "verification_error"
}

func observedTLSConfig(server bool, svid x509svid.Source, bundles x509bundle.Source, expected spiffeid.ID, observation *tlsObservation) *tls.Config {
	// Use the library's full chain/domain verifier; the wrapper only records its
	// result. Exact peer policy executes only after successful chain validation.
	authorize := func(id spiffeid.ID, _ [][]*x509.Certificate) error {
		if id != expected || id.Path() == "" {
			return errPeerPolicy
		}
		return nil
	}
	return observedTLSConfigWithPolicy(server, svid, bundles, authorize, observation)
}

func observedTLSConfigWithPolicy(server bool, svid x509svid.Source, bundles x509bundle.Source, authorize tlsconfig.Authorizer, observation *tlsObservation) *tls.Config {
	var config *tls.Config
	if server {
		config = tlsconfig.MTLSServerConfig(svid, bundles, authorize)
	} else {
		config = tlsconfig.MTLSClientConfig(svid, bundles, authorize)
	}
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	config.CurvePreferences = []tls.CurveID{tls.X25519}
	config.SessionTicketsDisabled = true
	verify := config.VerifyPeerCertificate
	config.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
		err := verify(raw, chains)
		observation.PeerVerification = verificationOutcome(err)
		if len(raw) > 0 {
			if cert, parseErr := x509.ParseCertificate(raw[0]); parseErr == nil {
				observation.PeerCertificateSHA256 = certificateHash(cert)
				observation.PeerSignature = cert.SignatureAlgorithm.String()
				if id, idErr := x509svid.IDFromCert(cert); idErr == nil {
					// An extracted identity is not an authenticated identity when
					// peer_verification is anything other than verified.
					observation.PeerID = id.String()
				}
			}
		}
		return err
	}
	return config
}

func finishObservation(observation *tlsObservation, tc *tls.Conn, err error, start time.Time) {
	observation.DurationMS = float64(time.Since(start)) / float64(time.Millisecond)
	observation.Accepted = err == nil
	if err != nil {
		observation.Error = err.Error()
	}
	state := tc.ConnectionState()
	observation.TLSVersion = state.Version
	if state.CipherSuite != 0 {
		observation.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	}
	observation.DidResume = state.DidResume
}

func serveTLSConnection(raw net.Conn, svid x509svid.Source, bundles x509bundle.Source, expected spiffeid.ID) tlsObservation {
	start := time.Now()
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	observation := tlsObservation{Event: "connection", PeerVerification: "not_reached"}
	tc := tls.Server(raw, observedTLSConfig(true, svid, bundles, expected, &observation))
	err := tc.Handshake()
	if err == nil {
		request := make([]byte, 1)
		_, err = io.ReadFull(tc, request)
		if err == nil && request[0] != '?' {
			err = errors.New("invalid lab request")
		}
		if err == nil {
			_, err = tc.Write([]byte("ok"))
		}
	}
	finishObservation(&observation, tc, err, start)
	return observation
}

func dialTLS(ctx context.Context, address string, svid x509svid.Source, bundles x509bundle.Source, expected spiffeid.ID) tlsObservation {
	start := time.Now()
	observation := tlsObservation{Event: "connection", PeerVerification: "not_reached"}
	raw, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		observation.Error = err.Error()
		observation.DurationMS = float64(time.Since(start)) / float64(time.Millisecond)
		return observation
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	tc := tls.Client(raw, observedTLSConfig(false, svid, bundles, expected, &observation))
	err = tc.HandshakeContext(ctx)
	if err == nil {
		_, err = tc.Write([]byte("?"))
	}
	if err == nil {
		response := make([]byte, 2)
		_, err = io.ReadFull(tc, response)
		if err == nil && string(response) != "ok" {
			err = errors.New("unexpected lab response")
		}
	}
	finishObservation(&observation, tc, err, start)
	return observation
}

func liveTLS(socket, selected, expected, role, address string) error {
	if !strings.HasPrefix(socket, "unix:///") {
		return errors.New("only explicit local unix:/// Workload API sockets supported")
	}
	if role != "server" && role != "client" {
		return errors.New("mtls-role must be server or client")
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return err
	}
	ownID, err := spiffeid.FromString(selected)
	if err != nil || ownID.Path() == "" {
		return errors.New("select-id must be an exact workload identity")
	}
	peerID, err := spiffeid.FromString(expected)
	if err != nil || peerID.Path() == "" {
		return errors.New("peer-id must be an exact workload identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	// Bound the initial Workload API fetch, while allowing the library's watcher
	// to maintain bundles for the remainder of the lab process.
	initCtx, stopInit := context.WithTimeout(ctx, 5*time.Second)
	defer stopInit()
	live, err := workloadapi.NewX509Source(initCtx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socket)),
		workloadapi.WithDefaultX509SVIDPicker(func(svids []*x509svid.SVID) *x509svid.SVID {
			for _, svid := range svids {
				if svid.ID == ownID {
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
	if err = validate(retained, live, ownID, time.Now()); err != nil {
		return err
	}
	// Both client and server retain their first SVID, while bundle lookup remains
	// live. This intentionally tests retained credentials, not automatic renewal.
	fixed := source{retained}
	out := json.NewEncoder(os.Stdout)
	ready := map[string]any{"event": "ready", "role": role, "id": ownID.String(), "certificate_sha256": certificateHash(retained.Certificates[0]), "not_before": retained.Certificates[0].NotBefore.Unix(), "not_after": retained.Certificates[0].NotAfter.Unix(), "pq_authenticated": false, "retained_credential": true}
	if role == "server" {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return err
		}
		defer listener.Close()
		stopClose := context.AfterFunc(ctx, func() { listener.Close() })
		defer stopClose()
		if err := out.Encode(ready); err != nil {
			return err
		}
		for attempts := 0; attempts < 512; attempts++ {
			raw, err := listener.Accept()
			if err != nil {
				return err
			}
			if err := out.Encode(serveTLSConnection(raw, fixed, live, peerID)); err != nil {
				return err
			}
		}
		return errors.New("lab connection limit exceeded")
	}
	if err := out.Encode(ready); err != nil {
		return err
	}
	stopInput := context.AfterFunc(ctx, func() { os.Stdin.Close() })
	defer stopInput()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 128), 128)
	for attempts := 0; scanner.Scan(); attempts++ {
		if attempts >= 512 || scanner.Text() != "probe" {
			return fmt.Errorf("invalid or excessive lab command")
		}
		if err := out.Encode(dialTLS(ctx, address, fixed, live, peerID)); err != nil {
			return err
		}
	}
	return scanner.Err()
}
