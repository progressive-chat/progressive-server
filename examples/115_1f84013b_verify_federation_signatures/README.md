# Step 115 — "feat: verify signatures for incoming requests" (Conduit `1f84013b`)

Source: [`timokoesters/conduit@1f84013b`](https://github.com/timokoesters/conduit/commit/1f84013b) (2021-04-21)

Straight-order intermediate `2f440e64` (clippy) is lint-only, no code change.

## What changed vs step 114

| Rust change | C++ translation |
|---|---|
| **Parse X-Matrix header (origin/key/sig), 580 on failure** | **Implemented** — `parse_x_matrix_params` (handles our unquoted-origin form too); failures → 401 `M_UNAUTHORIZED` (spec code instead of rocket's custom 580) |
| **Rebuild canonical `{content?, method, uri, origin, destination, signatures}`** | **Implemented** — byte-identical construction to our `sign_json` input (`nlohmann::json` objects sort keys, compact dump) |
| **Verify against origin keys (`fetch_signing_keys`)** | **Implemented** — cache (`get_signing_keys`) then live fetch of the origin's `/key/v2/server` doc (plain HTTP in the sandbox; production HTTPS) |
| **Enforced on every ServerSignatures endpoint** | **Implemented** — `require_federation_auth` guard on all `/_matrix/federation/*` routes; `/version`, `/key`, `.well-known` stay open (key bootstrapping, as upstream) |
| **Client Bearer tokens no longer accepted on federation routes** | **Implemented** — the two handlers that wrongly required user tokens (fed `publicRooms`, `state_ids`) now use the federation guard |
| **Request body size limit + reuse for downstream parsing** | **Documented** — httplib already buffers bodies; no separate limit plumbing in C++ |

## Also in this step

- **Crypto fix (prerequisite)**: `Ed25519Key` now accepts versioned keypairs (uses the trailing 32 bytes). Previously every signature made with a post-`dd749b8` keypair came out empty — this un-breaks all event/request signing (noted as pre-existing in step 108).
- **Restored routes lost in the step-112 edit**: `GET /event`, `GET /backfill`, `GET /state_ids/:room/:event` (all now behind the guard).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
