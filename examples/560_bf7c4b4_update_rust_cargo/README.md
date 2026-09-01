# Step 560 — "update rust to avoid a cargo problem" (Conduit `bf7c4b4`)

Source: [`timokoesters/conduit@bf7c4b4`](https://github.com/timokoesters/conduit/commit/bf7c4b4) (2022-10)

## What changed vs step 559

| Rust change | C++ translation |
|---|---|
| Update rust to avoid a cargo problem. Rust toolchain update. | **No-op for us** — Rust toolchain — N/A for C++. |

## Implementation details

- Rust toolchain — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
