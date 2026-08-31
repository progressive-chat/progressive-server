# Step 8 — "Store hashed passwords (#7)" (Conduit `fa9e127a`)

Source: [`timokoesters/conduit@fa9e127a`](https://github.com/timokoesters/conduit/commit/fa9e127a) (2020-04-14)

## What changed vs step 6

| Rust change | C++ translation |
|---|---|
| Replaces plaintext password storage with Argon2id hashes. Uses libargon2. The `password_hash_get` method on Data retrieves the hash for verification. M_FORBIDDEN for invalid login. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
