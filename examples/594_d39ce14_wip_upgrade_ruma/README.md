# Step 594 — "WIP: Upgrade Ruma" (Conduit `d39ce14`)

Source: [`timokoesters/conduit@d39ce14`](https://github.com/timokoesters/conduit/commit/d39ce14) (2022-12)

## What changed vs step 593

| Rust change | C++ translation |
|---|---|
| WIP: Upgrade Ruma. Major Ruma upgrade work in progress. 41 files changed. | **Skipped** — Rust dependency upgrade WIP — no direct C++ equivalent. |

## Implementation details

- Rust dependency upgrade WIP — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
