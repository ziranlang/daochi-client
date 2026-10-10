# Daochi Client

Native clients can import `daochi_client/crypto_native` for bounded byte-slice
SHA-256, streaming digests, HMAC-SHA-256, XChaCha20-Poly1305, secure random bytes,
clearing buffers and compatible Argon2id exports. Link libsodium for this optional
provider; it uses the same 24-byte nonces and appended authentication tags as
existing encrypted content. Applications retain their account and content keys,
authenticated schema context, storage, and node policy. `keys.ValidateIdentity`
verifies an existing binary ML-DSA-44 account and private-key proof without
creating or replacing keys.

Daochi Client is the independent Ziran library for applications that sync with
Daochi. It contains no server, mesh node, database, or UI implementation.
It has no Kryon dependency and lives in the
[Ziran organization](https://github.com/ziranlang/daochi-client). Add it with
`ziran add https://github.com/ziranlang/daochi-client.git`.

The protocol modules currently provide:

- canonical challenge, login body, and signed message builders (`wire.zi`);
- HTTPS and local network URL policy (`url.zi`);
- challenge parsing, signed login preparation, and token parsing (`auth.zi`);
- login and bearer requests with one fresh login after a `401` (`client.zi`);
- canonical device registration and protocol v6 transaction messages
  (`transaction.zi`);
- signed device registration and protocol v6 sync requests (`sync.zi`);
- encrypted record profile v1 (`daochi-record-v1`) envelopes with canonical
  authenticated metadata and fresh XChaCha20-Poly1305 nonces (`record.zi`,
  native; link libsodium);
- polled login, bearer requests, and signed sync operations
  (`async_client.zi`, `async_sync.zi`);
- alias and friend requests, actions, lists, and stats (`social.zi`);
- challenge signed account deletion without transmitting a key backup
  (`account.zi`).
- WebSocket URL, event validation, and one event wait through a host callback
  (`events.zi`).
- account keys: an ML-DSA-44 key pair with its SHA-256 public id, message
  signing, and the plain (`account-key-v1`) and passphrase-encrypted
  (`ksync-account-key-v2`) key files (`keys.zi`, signing through the Oqs
  package);
- SHA-256, HMAC-SHA-256, PBKDF2, and ChaCha20-Poly1305 (`crypto.zi`).

The application supplies the account signer and body digest; `keys.zi`
provides both for Daochi account keys (`SignAccountMessage`, `Sha256Hex`), and
the app still stores the keys. A host supplies
bounded HTTP requests through `SendRequest`; the host must NUL terminate every
response buffer, including on error. This keeps private keys in the app's key
store and keeps platform transport outside the protocol core. Applications
persist `Session` if they want bearer tokens to survive restart. Account keys
must remain when a bearer token expires.

Import the package modules with `#import "daochi_client/client"` and
`#import "daochi_client/sync"`. Set `Client.app_id`, supply a `Device` with a
persisted Ed25519 key and signer, and supply a cryptographically random 64-digit
hex nonce callback. `Sync` registers the device and signs the exact sync body
with both the account and device keys. The app owns the payload format and
merges the response. A native host can adapt `SendRequest` to Ziran's curl HTTP
module and `ReceiveEvent` to its bounded curl WebSocket module. Browser and
Android hosts must implement those host boundaries before those builds sync.

Event loops can use `BeginRequest`/`PollRequest` and `BeginSync`/`PollSync`
with `AsyncTransport`. Its start callback copies the request metadata and
retains the caller's bounded output buffer; poll returns `-1` while pending,
`0` for transport failure, or `1` with the HTTP status when complete. Every
completed response must be NUL terminated. Cancel releases all transport
references to that output buffer before returning. Keep the pending operation,
session, client identity, signing contexts, body, and extra header strings alive
until completion or cancellation. Each pending operation has its own transport
context. `CancelRequest` and `CancelSync` release an active transfer and finish
with `AUTH_REQUEST_FAILED`. Both request modes share the same one-login retry
after a `401`; sync modes share the exact registration and transaction builders.

`sh tests/run.sh` checks the library using the toolchain selected by
`ziran pkg path ziran`, including portable `.zib` URL and wire tests. An
ignored `ziran.local.toml` can select the local compiler at
`../../ziran`; otherwise the test uses `ziran.lock`. The wire
test also checks a saved `.zir` to `.zib` round trip. Set `ZIRAN_BIN` to use
a different launcher, or `ZIRAN_DIR` and `ZI2C_BIN` for explicit compiler
overrides.

The library does not provision keys, revoke devices, store account data, or
merge application records. Each app owns those operations and supplies its
payload builder, response merge, key store, and platform transport.

The protocol uses Ziran's `TextView` and bounded `TextUntilNul` instead of
a native string-layout adapter. URL policy, wire builders, and signed device
registration message construction compile and run as portable `.zib`. The
full HTTP client is **not yet a `.zib` bundle**: host transport, digest, and
signer callbacks need bundle capabilities. Native Linux integration is tested;
browser and Android transports remain application host work.

`sync.PrepareRequestHeader` prepares the same account/device signed v6
transaction for an exact HTTP method, path and byte-counted body, including
empty GET/HEAD bodies and binary blob uploads. Hosts that already stream and
hash the body can use `sync.SignTransactionHeader` with an explicit
`transaction.SyncTransaction`; its account, app and device must match the
supplied client. `PrepareSyncHeader` retains the existing POST sync behavior.
The host still owns transport, pinned-node policy, session/key storage and
remote acknowledgment handling.
