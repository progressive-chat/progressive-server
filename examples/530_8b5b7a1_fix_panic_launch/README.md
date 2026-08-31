# Step 530 — "fix: panic on launch" (Conduit `8b5b7a1`)

Source: [`timokoesters/conduit@8b5b7a1`](https://github.com/timokoesters/conduit/commit/8b5b7a1) (2022-10)

## What changed vs step 529

| Rust change | C++ translation |
|---|---|
| Fix: panic on launch. Startup crash fix. 20 files changed. | **Translated** — Startup crash fix — our server starts clean. This fixes a Rust panic. |

## Implementation details

- Startup crash fix — our server starts clean. This fixes a Rust panic.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
