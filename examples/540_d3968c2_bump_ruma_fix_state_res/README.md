# Step 540 — "fix: bump ruma again to fix state res problems" (Conduit `d3968c2`)

Source: [`timokoesters/conduit@d3968c2`](https://github.com/timokoesters/conduit/commit/d3968c2) (2022-10)

## What changed vs step 539

| Rust change | C++ translation |
|---|---|
| Fix: bump ruma again to fix state res problems. Ruma upgrade for state resolution fixes. 6 files changed. | **Skipped** — Rust dependency upgrade — no direct C++ equivalent. |

## Implementation details

- Rust dependency upgrade — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
