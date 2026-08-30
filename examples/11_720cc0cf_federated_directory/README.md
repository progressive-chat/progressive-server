# Step 11 — "feat: federated room directory" (Conduit `720cc0cf`)

Source: [`timokoesters/conduit@720cc0cf`](https://github.com/timokoesters/conduit/commit/720cc0cf) (2020-04-29)

## What changed vs step 10

| Rust change | C++ translation |
|---|---|
| Public rooms merge chunks from `chat.privacytools.io` (preserved verbatim in signed map). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
