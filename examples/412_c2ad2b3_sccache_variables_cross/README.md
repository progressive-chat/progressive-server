# Step 412 — "fix: pass sccache variables to cross container with build.env.passthrough" (Conduit `c2ad2b3`)

Source: [`timokoesters/conduit@c2ad2b3`](https://github.com/timokoesters/conduit/commit/c2ad2b3) (2022-01)

## What changed vs step 411

| Rust change | C++ translation |
|---|---|
| Fix: pass sccache variables to cross container with build.env.passthrough. Build cache for cross-compile. 2 files changed. | **No-op for us** — Rust build cache — N/A for C++. |

## Implementation details

- Rust build cache — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
