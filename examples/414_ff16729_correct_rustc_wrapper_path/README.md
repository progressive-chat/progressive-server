# Step 414 — "fix: correct RUSTC_WRAPPER path in cross container" (Conduit `ff16729`)

Source: [`timokoesters/conduit@ff16729`](https://github.com/timokoesters/conduit/commit/ff16729) (2022-01)

## What changed vs step 413

| Rust change | C++ translation |
|---|---|
| Fix: correct RUSTC_WRAPPER path in cross container. Cross-compile path fix. | **No-op for us** — Rust cross-compile — N/A for C++. |

## Implementation details

- Rust cross-compile — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
