# Step 325 — "Switch ruma to a commit from next" (Conduit `c30cc50`)

Source: [`timokoesters/conduit@c30cc50`](https://github.com/timokoesters/conduit/commit/c30cc50) (2021-07)

## What changed vs step 324

| Rust change | C++ translation |
|---|---|
| Switch ruma to a commit from next branch. Dependency update to ruma next. | **Skipped** — Rust dependency update — no direct C++ equivalent. |

## Implementation details

- Rust dependency update — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
