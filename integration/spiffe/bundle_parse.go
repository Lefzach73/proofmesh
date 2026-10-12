package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"proofmesh.local/research/internal/jsoncheck"
)

// SPIFFE Trust Domain and Bundle section 4.1 / RFC 7517 sections 4-6
// define case-sensitive JSON member names. The pinned spiffebundle parser
// uses encoding/json's case-insensitive struct matching for the outer object;
// go-jose already matches JWK members case-sensitively. Reject aliases before
// either parser can interpret or ignore them. Unknown extensions remain valid,
// and their contents are outside these registered-member namespaces.
func checkBundleJSON(raw []byte) error {
	if err := jsoncheck.Check(raw); err != nil {
		return err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return err
	}
	if err := canonicalBundleMembers(document, []string{"keys", "spiffe_sequence", "spiffe_refresh_hint"}); err != nil {
		return err
	}
	if rawKeys, ok := document["keys"]; ok {
		var keys []map[string]json.RawMessage
		if err := json.Unmarshal(rawKeys, &keys); err != nil {
			return err
		}
		for _, key := range keys {
			// RFC 7517 common members and the RFC 7518/8037 key parameters
			// supported by the pinned go-jose parser. Preserve x5t#S256's
			// registered mixed case; do not lowercase or reserialize input.
			if err := canonicalBundleMembers(key, []string{
				"kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256",
				"crv", "x", "y", "n", "e", "k", "d", "p", "q", "dp", "dq", "qi",
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func canonicalBundleMembers(object map[string]json.RawMessage, registered []string) error {
	for name := range object {
		for _, canonical := range registered {
			// EqualFold also catches the Unicode folds accepted by encoding/json.
			if name != canonical && strings.EqualFold(name, canonical) {
				return fmt.Errorf("noncanonical bundle member %q; expected %q", name, canonical)
			}
		}
	}
	return nil
}
