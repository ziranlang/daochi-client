# Delegated authorization

The existing account login and protocol v6 transaction APIs retain their released
wire format. Delegate credentials are a separate type. They never populate
`HttpRequest.token` and never go through `BearerRequest`.

An owner creates a pending request using `BuildAuthorizationRequest` and
`OwnerAuthorizationRequest`. These owner requests require the existing ML-DSA
owner signature and registered Ed25519 device signature; the authorization helper
admits only requests, cancel and revoke routes. Public rendezvous polling reveals
only expiring request/grant identifiers, app, node, audience, challenge and status.
`ReadPublicRendezvous` rejects owner metadata. `ReadOwnerRendezvous` consumes the
owner-authenticated view for the app's approval UI.

A delegate uses a host-supplied Ed25519 signer and a separate ML-KEM-768 recipient
key. `BuildClaimMessage` and `BuildClaimBody` prepare a proof of possession. The
raw Telegram initData travels to the issuing server for authentication. A digest
supplied to the claim builder is the server's canonical SHA-256 digest of bot ID,
newline, and sorted decoded initData fields except `hash`; calculating that digest
in a client does not authenticate the Telegram user.

The owner must approve the actual app, account, verified numeric Telegram user
when present, exact collections, operations, visibility, key generation, delegate
keys and finite expiry. `PrepareGrantApproval` signs the immutable grant once.
Collection scopes are sorted, exact names; no wildcards, account metadata or
legacy combined Inbe private collections are admitted. This approval UI and any
cross-device comparison belong to the application. Opening a link or validating
Telegram data supplies neither owner consent nor recovery of owner keys.

`SealCollectionKey` wraps exactly one 32-byte approved collection key with
ML-KEM-768 and ChaCha20-Poly1305. It binds account, grant, issuing node, app,
collection, key generation and the recipient public-key hash as authenticated
data. `OpenCollectionKey` clears the supplied destination before every validation
and leaves it zero on failure. The node stores the envelope as opaque text, whose
hash is bound by the owner signature. The library never stores master keys,
delegate keys, sessions, recovery data or tokens.

A `DelegateClient` requires a host `CurrentTime(context)` callback returning current
Unix seconds. Every challenge/session validation and request-signing stage reads
it again, including after each async transfer. Missing or invalid clocks fail
closed; no handshake start time or supplied `now` argument is used as a fallback.
A `DelegateClient` contains the expected grant identity, app, client, issuing node,
audience, signing/encryption public keys, verified bot/user identity pair and requested scopes. Its `GrantStorage`
contains owned decoded values; `ViewGrant(storage, scopes, output)` creates a
borrowed view while those buffers remain alive. `AcceptSessionAnswer` validates
the owner public-key hash against the account identity and verifies the real
ML-DSA signature before installing the grant. It also checks every expected
binding and the exact requested scope list. Hosts must not change their expected
bindings to match an untrusted response.

`RenewDelegateSession` or `BeginDelegateSession` obtains a fresh challenge lasting
at most 90 seconds and signs it with the delegate key. Sessions last at most five
minutes and cannot outlive the grant. `BuildDelegatedSyncBody` admits only the
approved collection/key generation. `DelegateRequest` and
`BeginDelegateRequest` sign the method, normalized route/query, exact body hash,
grant, session, challenge, account, app, client, node, audience, short expiry and
unique nonce. Only delegated sync and collection-scoped WebSocket routes have
proof builders. A new nonce is required for every request. A 401/403 clears the
session; the host can explicitly renew with a fresh challenge. The async request
can renew an expired session before its first mutation, and holds all request
buffers until polling completes or its owned transfer is cancelled.

This is a custom Daochi wire protocol using sender-bound proof and replay
principles, not OAuth DPoP. Server revocation, current app visibility/status and
issuing-node checks remain authoritative on every request. Grants do not authorize
other nodes, grant chaining, exports, deletion, payments or owner routes. Revocation
blocks future access; it cannot erase already received keys or plaintext.
