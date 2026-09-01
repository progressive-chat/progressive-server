# Step 638 — "Bump Ruma" (Conduit `f53ecaa`)

Source: [`timokoesters/conduit@f53ecaa`](https://github.com/timokoesters/conduit/commit/f53ecaa) (2023-03)

## What changed vs step 637

| Rust change | C++ translation |
|---|---|
| Bump Ruma. Major Ruma version upgrade. 17 files changed. | **Skipped** — Rust dependency upgrade — no direct C++ equivalent. |

## Implementation details

- Rust dependency upgrade — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
