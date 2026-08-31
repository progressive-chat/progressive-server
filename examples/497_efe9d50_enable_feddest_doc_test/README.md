# Step 497 — "enable FedDest doc-test" (Conduit `efe9d50`)

Source: [`timokoesters/conduit@efe9d50`](https://github.com/timokoesters/conduit/commit/efe9d50) (2022-04)

## What changed vs step 496

| Rust change | C++ translation |
|---|---|
| Enable FedDest doc-test. Documentation test enablement. | **No-op for us** — Rust doc test — N/A for C++. |

## Implementation details

- Rust doc test — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
