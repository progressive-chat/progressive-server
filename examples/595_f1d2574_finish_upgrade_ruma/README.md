# Step 595 — "finish upgrade ruma" (Conduit `f1d2574`)

Source: [`timokoesters/conduit@f1d2574`](https://github.com/timokoesters/conduit/commit/f1d2574) (2022-12)

## What changed vs step 594

| Rust change | C++ translation |
|---|---|
| Finish upgrade ruma. Complete the major Ruma upgrade. 6 files changed. | **Skipped** — Rust dependency upgrade complete — no direct C++ equivalent. |

## Implementation details

- Rust dependency upgrade complete — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
