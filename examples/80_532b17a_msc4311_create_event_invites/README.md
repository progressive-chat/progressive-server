# Step 80 — "feat: MSC4311, Ensuring the create event is available on invites and knocks" (Conduit `532b17a`)

Source: [`timokoesters/conduit@532b17a`](https://github.com/timokoesters/conduit/commit/532b17a) (2025-08-11)

## What changed vs step 83

| Rust change | C++ translation |
|---|---|
| Federation invite/knock includes the create event in `auth_chain` (MSC4311). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
