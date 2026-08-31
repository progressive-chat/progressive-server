# Step 471 — "chore(ci): Split up tests" (Conduit `8f063c9`)

Source: [`timokoesters/conduit@8f063c9`](https://github.com/timokoesters/conduit/commit/8f063c9) (2022-02)

## What changed vs step 470

| Rust change | C++ translation |
|---|---|
| Chore(ci): Split up tests. CI test organization. | **No-op for us** — Rust CI test organization — N/A for C++. |

## Implementation details

- Rust CI test organization — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
