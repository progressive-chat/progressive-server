# Step 74 — "fix: avoid pdus without event ids" (Conduit `af53485`)

Source: [`timokoesters/conduit@af53485`](https://github.com/timokoesters/conduit/commit/af53485) (2020-09)

## What changed vs step 73

| Rust change | C++ translation |
|---|---|
| Bug fix: ensure every PDU has an event_id before being processed. Adds validation in the PDU builder. | **No-op for us** — our PDU generation always includes event_id (computed via `crypto::reference_hash`). |

## Implementation details

- **No-op for us** — our PDU generation always includes event_id (computed via `crypto::reference_hash`).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
