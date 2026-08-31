# Step 529 — "cargo fix" (Conduit `50b0eb9`)

Source: [`timokoesters/conduit@50b0eb9`](https://github.com/timokoesters/conduit/commit/50b0eb9) (2022-10)

## What changed vs step 528

| Rust change | C++ translation |
|---|---|
| Cargo fix. More automated fixes. 22 files changed. | **No-op for us** — Rust cargo fix — N/A for C++. |

## Implementation details

- Rust cargo fix — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
