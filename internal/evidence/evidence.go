package evidence

type Outcome string

const (
	Accept        Outcome = "ACCEPT"
	Reject        Outcome = "REJECT"
	Indeterminate Outcome = "INDETERMINATE"
)

type Reason string

const (
	Authorized        Reason = "AUTHORIZED"
	MalformedIdentity Reason = "MALFORMED_IDENTITY"
	Expired           Reason = "EXPIRED_SVID"
	NotYetValid       Reason = "NOT_YET_VALID_SVID"
	MissingBundle     Reason = "MISSING_BUNDLE"
	StaleBundle       Reason = "STALE_BUNDLE"
	WrongDomain       Reason = "WRONG_DOMAIN"
	IdentityMismatch  Reason = "IDENTITY_MISMATCH"
	RevokedIssuer     Reason = "REVOKED_ISSUER"
	Replay            Reason = "REPLAY"
	PolicyDenied      Reason = "POLICY_DENIED"
	CryptoMismatch    Reason = "CRYPTO_PROFILE_MISMATCH"
	UnknownState      Reason = "UNKNOWN_VERIFIER_STATE"
	InvalidSignature  Reason = "INVALID_SIGNATURE"
	Rollback          Reason = "BUNDLE_ROLLBACK"
	SequenceRequired  Reason = "SEQUENCE_REQUIRED"
	SequenceConflict  Reason = "SEQUENCE_CONFLICT"
	Unauthenticated   Reason = "UNAUTHENTICATED_BUNDLE"
	Unversioned       Reason = "UNVERSIONED"
	Updated           Reason = "BUNDLE_UPDATED"
	Partitioned       Reason = "PARTITIONED"
	Dropped           Reason = "DROPPED_UPDATE"
	EpochMismatch     Reason = "POLICY_EPOCH_MISMATCH"
)

type Decision struct {
	Outcome                   Outcome  `json:"outcome"`
	Reason                    Reason   `json:"reason"`
	Assertions                []Reason `json:"assertions"`
	BundleDomain              string   `json:"bundle_domain"`
	BundleSequence            *uint64  `json:"bundle_sequence"`
	BundleEpoch               uint64   `json:"bundle_epoch"`
	BundleAge                 int64    `json:"bundle_age_seconds"`
	CredentialHash            string   `json:"credential_descriptor_sha256"`
	Issuer                    string   `json:"synthetic_issuer"`
	KeyExchangeProfile        string   `json:"key_exchange_profile"`
	PeerAuthenticationProfile string   `json:"peer_authentication_profile"`
	PQAuthenticated           bool     `json:"pq_authenticated"`
	VerificationMode          string   `json:"verification_mode"`
}
