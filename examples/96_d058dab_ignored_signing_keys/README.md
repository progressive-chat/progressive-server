# Step 96 — "feat: add option to ignore specific server signing keys" (Conduit `d058dab`)

Source: [`timokoesters/conduit@d058dab`](https://github.com/timokoesters/conduit/commit/d058dab) (2026-02-12)

## What changed vs step 97

| Rust change | C++ translation |
|---|---|
| Adds `ignored_server_signing_keys` config option to skip validating keys from specific servers. Not implemented (we don't have a config layer). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
