# Step 527 — "cargo fix" (Conduit `f47a5cd`)

Source: [`timokoesters/conduit@f47a5cd`](https://github.com/timokoesters/conduit/commit/f47a5cd) (2022-10)

## What changed vs step 526

| Rust change | C++ translation |
|---|---|
| Cargo fix. Automated fix application. | **No-op for us** — Rust cargo fix — N/A for C++. |

## Implementation details

- Rust cargo fix — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
