# Step 261 — "improvement: update ruma" (Conduit `6e84d31`)

Source: [`timokoesters/conduit@6e84d31`](https://github.com/timokoesters/conduit/commit/6e84d31) (2021-04)

## What changed vs step 260

| Rust change | C++ translation |
|---|---|
| Improvement: update ruma. 8 files changed. Ruma library upgrade with API changes. | **Skipped** — Rust library upgrade — no direct C++ equivalent. |

## Implementation details

- Rust library upgrade — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
