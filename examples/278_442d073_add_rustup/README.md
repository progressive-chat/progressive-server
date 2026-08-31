# Step 278 — "add rustup" (Conduit `442d073`)

Source: [`timokoesters/conduit@442d073`](https://github.com/timokoesters/conduit/commit/442d073) (2021-05)

## What changed vs step 277

| Rust change | C++ translation |
|---|---|
| Add rustup. CI/tooling change. | **No-op for us** — Rust toolchain management — N/A for C++. |

## Implementation details

- Rust toolchain management — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
