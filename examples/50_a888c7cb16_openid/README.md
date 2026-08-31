# Step 50 — "OpenID routes" (Conduit `a888c7cb16`)

Source: [`timokoesters/conduit@a888c7cb16`](https://github.com/timokoesters/conduit/commit/a888c7cb16) (2024-05-28)

## What changed vs step 58

| Rust change | C++ translation |
|---|---|
| Adds `POST /user/{userId}/openid/request_token` minting an OpenID access token. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
