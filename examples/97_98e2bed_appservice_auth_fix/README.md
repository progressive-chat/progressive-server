# Step 97 — "fix: don't perform identity assertion on appservice-only endpoints" (Conduit `98e2bed`)

Source: [`timokoesters/conduit@98e2bed`](https://github.com/timokoesters/conduit/commit/98e2bed) (2026-01-22)

## What changed vs step 96

| Rust change | C++ translation |
|---|---|
| Appservice ping endpoint only accepts `AuthScheme::AppserviceToken` (matched via `appservice_id_from_token`). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
