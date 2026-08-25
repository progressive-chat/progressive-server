# Step 10 — "More work on federation" (Conduit `1af6dd98`, 2020-04-22)

Source: [`timokoesters/conduit@1af6dd98`](https://github.com/timokoesters/conduit/commit/1af6dd98)
— the **server side** of federation: Conduit publishes its identity so any
other homeserver can verify its signatures.

## What changed vs step 9

| Rust change | C++ translation |
|---|---|
| `GET /.well-known/matrix/server` — delegation hint (upstream hardcoded its test domain) | advertises our own hostname |
| `GET /_matrix/federation/v1/version` → `{"server":{"name":"Conduit","version":…}}` | identical |
| `GET /_matrix/key/v2/server` (+ deprecated `/key/v2/server/:key_id`) — signed server-key document: `verify_keys`, `old_verify_keys`, `valid_until_ts = now+24h`, self-signed via `sign_json` | `crypto::sign_json` (signatures-only sibling of `hash_and_sign_event`) + route handler; key id = `"ed25519:" + raw_public_base64url` |

## Verified

```console
$ curl http://127.0.0.1:8000/.well-known/matrix/server
{"m.server":"localhost"}

$ curl http://127.0.0.1:8000/_matrix/key/v2/server
{"old_verify_keys":{}, "server_name":"localhost",
 "signatures":{"localhost":{"ed25519:SmKS86…":"Amnb3k1s…"}},
 "valid_until_ts":1787761144912,
 "verify_keys":{"ed25519:SmKS86…":{"kty":"OKP","key":"SmKS86…"}}}
```

New test scenarios (all passing):
1. **key document self-signature verifies** — fetch the doc, strip
   `signatures`, verify with the embedded `verify_keys` entry.
2. **event signature verifies against published key** — take a synced PDU,
   ignore the event's embedded key, and verify using ONLY the fetched key
   document. This is exactly what a federating homeserver does on first
   contact.

## Build & run

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```

## Study note

With this step the trust model closes: step 9 made signatures *exist*;
step 10 makes them *checkable by strangers*. Every Matrix server pair ever
federated started with precisely these two HTTP documents.
