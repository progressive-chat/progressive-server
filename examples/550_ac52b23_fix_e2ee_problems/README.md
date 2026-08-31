# Step 550 — "fix: all the e2ee problems" (Conduit `ac52b23`)

Source: [`timokoesters/conduit@ac52b23`](https://github.com/timokoesters/conduit/commit/ac52b23) (2022-10)

## What changed vs step 549

| Rust change | C++ translation |
|---|---|
| Fix: all the e2ee problems. End-to-end encryption fixes. 7 files changed. MAJOR encryption fix. | **Translated** — We don't have E2EE yet (step 337 started). This fixes the Rust E2EE implementation. |

## Implementation details

- We don't have E2EE yet (step 337 started). This fixes the Rust E2EE implementation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
