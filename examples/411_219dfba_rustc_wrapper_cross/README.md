# Step 411 — "fix: pass RUSTC_WRAPPER to the cross container and enforce static builds" (Conduit `219dfba`)

Source: [`timokoesters/conduit@219dfba`](https://github.com/timokoesters/conduit/commit/219dfba) (2022-01)

## What changed vs step 410

| Rust change | C++ translation |
|---|---|
| Fix: pass RUSTC_WRAPPER to the cross container and enforce static builds. Cross-compile tooling. 3 files changed. | **No-op for us** — Rust cross-compile tooling — N/A for C++. |

## Implementation details

- Rust cross-compile tooling — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
