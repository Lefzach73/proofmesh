package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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

// Persistent TLS connections carry only a fixed one-byte lab operation. The
// plaintext response is fixed length too; it is sent INSIDE authenticated TLS.
// Control commands and labels are not part of the application protocol.
func serveApplicationConnection(ctx context.Context, raw net.Conn, svid x509svid.Source, gate *applicationGate, arm string, connection uint64, emit func(any)) {
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	start := time.Now()
	_ = raw.SetDeadline(start.Add(3 * time.Second))
	observation := tlsObservation{Event: "application-handshake", PeerVerification: "not_reached"}
	tc := tls.Server(raw, observedTLSConfigWithPolicy(true, svid, gate, gate.authorize, &observation))
	err := tc.HandshakeContext(ctx)
	if err == nil {
		_, err = tc.Write([]byte("hi"))
	}
	finishObservation(&observation, tc, err, start)
	emit(map[string]any{"event": "application-handshake", "connection_id": connection, "arm": arm, "tls": observation})
	if err != nil {
		return
	}
	_ = tc.SetDeadline(time.Time{})
	for request := 1; request <= 128; request++ {
		var row map[string]any
		if gate.requestProtocol {
			// Idle sessions are bounded by the lab lifetime/connection quota.
			// Once a frame starts, its remainder has a three-second deadline.
			var header [2]byte
			if _, err = io.ReadFull(tc, header[:1]); err != nil {
				return
			}
			_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err = io.ReadFull(tc, header[1:]); err != nil {
				return
			}
			size := int(binary.BigEndian.Uint16(header[:]))
			if size < 1 || size > 4096 {
				emit(map[string]any{"event": "application-protocol-error", "connection_id": connection, "arm": arm, "error": "request frame size invalid"})
				return
			}
			raw := make([]byte, size)
			if _, err = io.ReadFull(tc, raw); err != nil {
				return
			}
			_ = tc.SetReadDeadline(time.Time{})
			row = gate.executeRequest(tc.ConnectionState().PeerCertificates, arm, raw)
		} else {
			var input [1]byte
			if _, err = io.ReadFull(tc, input[:]); err != nil {
				return
			}
			if input[0] != '?' {
				emit(map[string]any{"event": "application-protocol-error", "connection_id": connection})
				return
			}
			row = gate.execute(tc.ConnectionState().PeerCertificates, arm)
		}
		row["connection_id"], row["request_index"] = connection, request
		response := "no"
		if row["handler_executed"] == true {
			response = "ok"
		}
		if row["commit_unknown"] == true {
			response = "er"
		}
		// The update/decision/effect linearization precedes response delivery.
		// We do not claim cancellation of already committed effects.
		_ = tc.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, err = tc.Write([]byte(response))
		row["response_written"] = err == nil
		if err != nil {
			row["transport_error"] = err.Error()
		}
		emit(row)
		if err != nil {
			return
		}
	}
}

type applicationSession struct{ conn *tls.Conn }

func (s *applicationSession) close() {
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

func (s *applicationSession) connect(ctx context.Context, address string, fixed x509svid.Source, bundles x509bundle.Source, peer spiffeid.ID) tlsObservation {
	s.close()
	start := time.Now()
	o := tlsObservation{Event: "application-connect", PeerVerification: "not_reached"}
	raw, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		o.Error = err.Error()
		return o
	}
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	tc := tls.Client(raw, observedTLSConfig(false, fixed, bundles, peer, &o))
	err = tc.HandshakeContext(ctx)
	if err == nil {
		var greeting [2]byte
		_, err = io.ReadFull(tc, greeting[:])
		if err == nil && string(greeting[:]) != "hi" {
			err = errors.New("invalid application greeting")
		}
	}
	finishObservation(&o, tc, err, start)
	if err != nil {
		tc.Close()
	} else {
		s.conn = tc
		_ = tc.SetDeadline(time.Time{})
	}
	return o
}

func (s *applicationSession) request() map[string]any {
	return s.sendApplication([]byte("?"), false)
}

func (s *applicationSession) requestJSON(payload string) map[string]any {
	if len(payload) < 1 || len(payload) > 4096 {
		return map[string]any{"event": "application-response", "transport_success": false, "accepted": false, "error": "request payload size invalid"}
	}
	raw := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(raw[:2], uint16(len(payload)))
	copy(raw[2:], payload)
	return s.sendApplication(raw, true)
}

func (s *applicationSession) sendApplication(raw []byte, rich bool) map[string]any {
	r := map[string]any{"event": "application-response", "transport_success": false, "accepted": false, "pq_authenticated": false}
	if s.conn == nil {
		r["error"] = "no connected mTLS session"
		return r
	}
	_ = s.conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err := s.conn.Write(raw)
	var response [2]byte
	if err == nil {
		_, err = io.ReadFull(s.conn, response[:])
	}
	if err == nil && string(response[:]) != "ok" && string(response[:]) != "no" && !(rich && string(response[:]) == "er") {
		err = errors.New("invalid application response")
	}
	if err != nil {
		r["error"] = err.Error()
		s.close()
		return r
	}
	r["transport_success"], r["accepted"] = true, string(response[:]) == "ok"
	if rich {
		r["commit_unknown"] = string(response[:]) == "er"
	}
	_ = s.conn.SetDeadline(time.Time{})
	return r
}

func applicationTLS(socket, selected, expected, role, address, allowedNames, endpoint, endpointName, statePath, protocol string, budget int, allowTestCrash bool) error {
	if protocol != "fixed-v1" && protocol != "request-v1" {
		return errors.New("unsupported application protocol")
	}
	if !strings.HasPrefix(socket, "unix:///") || (role != "server" && role != "client") {
		return errors.New("explicit local socket and application-role server/client required")
	}
	own, err := spiffeid.FromString(selected)
	if err != nil || own.Path() == "" {
		return errors.New("exact select-id required")
	}
	peer, err := spiffeid.FromString(expected)
	if err != nil || peer.Path() == "" {
		return errors.New("exact peer-id required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	initCtx, initCancel := context.WithTimeout(ctx, 5*time.Second)
	defer initCancel()
	live, err := workloadapi.NewX509Source(initCtx, workloadapi.WithClientOptions(workloadapi.WithAddr(socket)), workloadapi.WithDefaultX509SVIDPicker(func(svids []*x509svid.SVID) *x509svid.SVID {
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
	fixed := source{retained}
	var outMu sync.Mutex
	out := json.NewEncoder(os.Stdout)
	emit := func(row any) {
		outMu.Lock()
		defer outMu.Unlock()
		if out.Encode(row) != nil {
			cancel()
		}
	}
	ready := map[string]any{"event": "ready", "role": role, "id": own.String(), "certificate_sha256": certificateHash(retained.Certificates[0]), "pq_authenticated": false, "retained_credential": true, "cache_persistence": "volatile"}
	ready["not_before"], ready["not_after"] = retained.Certificates[0].NotBefore.Unix(), retained.Certificates[0].NotAfter.Unix()
	ready["test_crash_enabled"] = allowTestCrash
	ready["application_protocol"] = protocol
	ready["process_uid"] = os.Getuid()
	stopInput := context.AfterFunc(ctx, func() { os.Stdin.Close() })
	defer stopInput()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 4096)
	var gate *applicationGate
	var endpointID spiffeid.ID
	var sessions sync.WaitGroup
	if role == "server" {
		if budget != 0 && budget != 3 && budget != 120 {
			return errors.New("lab budget must be 0, 3 or 120")
		}
		endpointID, err = spiffeid.FromString(endpointName)
		if err != nil || endpointID.Path() == "" || endpointID.TrustDomain() != peer.TrustDomain() || endpoint == "" {
			return errors.New("authenticated endpoint must bind peer domain")
		}
		allowed := []spiffeid.ID{}
		for _, name := range strings.Split(allowedNames, ",") {
			id, err := spiffeid.FromString(name)
			if err != nil || id.Path() == "" || id.TrustDomain() != peer.TrustDomain() {
				return errors.New("every allowed peer must be exact and in endpoint domain")
			}
			allowed = append(allowed, id)
		}
		if len(allowed) > 16 {
			return errors.New("too many lab peers")
		}
		gate = newApplicationGate(own, allowed, peer.TrustDomain())
		arms := []string{"B0.direct", fmt.Sprintf("B2/%d", budget), fmt.Sprintf("B3/%d", budget)}
		if statePath != "" {
			if err := gate.enablePersistence(ctx, statePath, time.Now()); err != nil {
				return err
			}
			defer gate.close()
			ready["cache_persistence"] = "durable-public-trust"
			ready["restored_snapshot"], ready["security_records"], ready["clock_high_water"] = gate.cache.summary(), gate.cache.store.Records(), gate.disk.clock
		}
		if protocol == "request-v1" {
			if err := gate.enableRequestProtocol(arms); err != nil {
				return err
			}
			ready["restored_counters"], ready["retained_request_ids"] = gate.requests.counters, len(gate.requests.seen)
			ready["request_id_scope"] = "experimental arm, authenticated SPIFFE caller, request ID; fixed target/action"
		}
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65533 {
			return errors.New("invalid base listen port")
		}
		listeners := []net.Listener{}
		// Clean up partial listener creation, cancel blocked requests, then join.
		defer func() {
			cancel()
			for _, listener := range listeners {
				listener.Close()
			}
			sessions.Wait()
		}()
		var sequence atomic.Uint64
		slots := make(chan struct{}, 16)
		ready["arms"] = arms
		for index, arm := range arms {
			listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port+index)))
			if err != nil {
				return err
			}
			listeners = append(listeners, listener)
			sessions.Add(1)
			go func() {
				defer sessions.Done()
				stop := context.AfterFunc(ctx, func() { listener.Close() })
				defer stop()
				for {
					raw, err := listener.Accept()
					if err != nil {
						return
					}
					id := sequence.Add(1)
					if id > 128 {
						raw.Close()
						cancel()
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
						serveApplicationConnection(ctx, raw, fixed, gate, arm, id, emit)
					}()
				}
			}()
		}
	}
	emit(ready)
	session := &applicationSession{}
	defer session.close()
	for count := 0; scanner.Scan(); count++ {
		if count >= 512 {
			return errors.New("lab command limit exceeded")
		}
		if err := jsoncheck.Check(scanner.Bytes()); err != nil {
			return err
		}
		var command struct {
			Op      string `json:"op"`
			Payload string `json:"payload,omitempty"`
		}
		decoder := json.NewDecoder(strings.NewReader(scanner.Text()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&command); err != nil {
			return err
		}
		if role == "server" {
			if command.Payload != "" {
				return errors.New("server control does not accept application payload")
			}
			switch command.Op {
			case "refresh":
				emit(gate.refresh(ctx, endpoint, endpointID, live))
			case "remove":
				emit(gate.removeTrust(ctx))
			case "test-crash":
				if !allowTestCrash || statePath == "" {
					return errors.New("explicit durable lab crash flag required")
				}
				// Distroless SPIRE has no shell/kill executable. Only this process
				// can be terminated, and only by its opted-in local control pipe.
				process, err := os.FindProcess(os.Getpid())
				if err != nil {
					return err
				}
				return process.Kill()
			default:
				return errors.New("unknown application server control command")
			}
		} else {
			switch command.Op {
			case "connect":
				emit(session.connect(ctx, address, fixed, live, peer))
			case "request":
				if protocol == "request-v1" {
					emit(session.requestJSON(command.Payload))
				} else {
					if command.Payload != "" {
						return errors.New("fixed-v1 does not accept client-controlled payloads")
					}
					emit(session.request())
				}
			case "close":
				session.close()
				emit(map[string]any{"event": "application-closed"})
			default:
				return errors.New("unknown application client command")
			}
		}
	}
	return scanner.Err()
}
