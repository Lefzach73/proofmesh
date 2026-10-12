package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
)

func TestAuthenticatedBundleCanonicalMemberNames(t *testing.T) {
	ca, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := ca.issue("spiffe://beta.local/publisher", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	b := spiffebundle.FromX509Authorities(ca.domain, []*x509.Certificate{ca.cert})
	b.SetSequenceNumber(12)
	b.SetRefreshHint(30 * time.Second)
	body, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	var keys []json.RawMessage
	if err := json.Unmarshal(document["keys"], &keys); err != nil {
		t.Fatal(err)
	}
	keyWith := func(member string) string {
		return `{"keys":[` + string(keys[0][:len(keys[0])-1]) + `,` + member + `}],"spiffe_sequence":12,"spiffe_refresh_hint":30}`
	}
	thumbprint := sha256.Sum256(ca.cert.Raw)
	extensions := keyWith(`"example_extension":{"USE":1,"KEYS":2}`)
	extensions = extensions[:len(extensions)-1] + `,"example_extension":{"KEYS":1,"SPIFFE_SEQUENCE":2}}`
	cases := []struct {
		name, raw string
		accept    bool
	}{
		{"canonical", string(body), true},
		{"empty", `{"keys":[],"spiffe_sequence":12,"spiffe_refresh_hint":30}`, true},
		{"unversioned", `{"keys":[]}`, true},
		{"extensions", extensions, true},
		{"canonical-thumbprint", keyWith(`"x5t#S256":"` + base64.RawURLEncoding.EncodeToString(thumbprint[:]) + `"`), true},
		{"sequence-alias-after", `{"keys":[],"spiffe_sequence":11,"SPIFFE_SEQUENCE":13}`, false},
		{"sequence-alias-before", `{"keys":[],"SPIFFE_SEQUENCE":13,"spiffe_sequence":11}`, false},
		{"sequence-alias-only", `{"keys":[],"SPIFFE_SEQUENCE":13}`, false},
		{"keys-alias", `{"keys":[],"KEYS":` + string(document["keys"]) + `}`, false},
		{"keys-alias-only", `{"Keys":[]}`, false},
		{"unicode-fold-alias", `{"keys":[],"\u212aEYS":[]}`, false},
		{"hint-alias", `{"keys":[],"spiffe_refresh_hint":30,"SPIFFE_REFRESH_HINT":40}`, false},
		{"duplicate-keys", `{"keys":[],"keys":[]}`, false},
		{"escaped-duplicate", `{"keys":[],"\u006beys":[]}`, false},
		{"jwk-use-alias", keyWith(`"USE":"x509-svid"`), false},
		{"jwk-type-alias", keyWith(`"KTY":"EC"`), false},
		{"jwk-certificate-alias", keyWith(`"X5C":[]`), false},
		{"jwk-thumbprint-alias", keyWith(`"x5t#s256":"ignored"`), false},
		{"jwk-id-alias", keyWith(`"KID":"ignored"`), false},
		{"trailing-document", string(body) + `{}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			web := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.raw))
			}))
			web.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{endpoint.Certificates[0].Raw}, PrivateKey: endpoint.PrivateKey}}}
			web.StartTLS()
			defer web.Close()
			fetched, err := fetchAuthenticatedBundle(context.Background(), web.URL, endpoint.ID, ca.bundle())
			if (err == nil) != tc.accept {
				t.Fatalf("accepted=%v, want %v; error=%v", err == nil, tc.accept, err)
			}
			if err != nil {
				return
			}
			sequence, present := fetched.bundle.SequenceNumber()
			if tc.name == "unversioned" {
				if present {
					t.Fatal("invented sequence")
				}
				return
			}
			if !present || sequence != 12 {
				t.Fatal("changed canonical sequence", sequence, present)
			}
			if hint, ok := fetched.bundle.RefreshHint(); !ok || hint != 30*time.Second {
				t.Fatal("changed canonical refresh hint", hint, ok)
			}
			wantAuthorities := 1
			if tc.name == "empty" {
				wantAuthorities = 0
			}
			if got := len(fetched.bundle.X509Authorities()); got != wantAuthorities {
				t.Fatal("changed canonical authorities", got)
			}
			hash := sha256.Sum256([]byte(tc.raw))
			if fetched.bodySHA256 != hex.EncodeToString(hash[:]) {
				t.Fatal("changed original response digest")
			}
		})
	}
}
