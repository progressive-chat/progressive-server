# Step 1 — "Initial commit" (Conduit `6264628c`)

Source: [`timokoesters/conduit@6264628c`](https://github.com/timokoesters/conduit/commit/6264628c) (2020-02-15)

## What changed vs step 0

| Rust change | C++ translation |
|---|---|
| Conduit's first commit. Sets up the Rocket-based Matrix homeserver skeleton with `main.rs` (request routing), `database.rs` (sled persistence), and `ruma_wrapper.rs` (Matrix type wrappers). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
