# Step 263 — "Refactor Responder implementation for RumaResponse" (Conduit `7067d7a`)

Source: [`timokoesters/conduit@7067d7a`](https://github.com/timokoesters/conduit/commit/7067d7a) (2021-04)

## What changed vs step 262

| Rust change | C++ translation |
|---|---|
| Refactor Responder implementation for RumaResponse. Rust web framework internal change. | **No-op for us** — Rust Ruma framework internal — our httplib handles responses differently. |

## Implementation details

- Rust Ruma framework internal — our httplib handles responses differently.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
