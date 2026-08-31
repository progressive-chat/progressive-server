# Step 438 — "Upgrade Ruma" (Conduit `d23d6fb`)

Source: [`timokoesters/conduit@d23d6fb`](https://github.com/timokoesters/conduit/commit/d23d6fb) (2022-02)

## What changed vs step 437

| Rust change | C++ translation |
|---|---|
| Upgrade Ruma. Dependency version bump. 3 files changed. | **Skipped** — Rust dependency upgrade — no direct C++ equivalent. |

## Implementation details

- Rust dependency upgrade — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
