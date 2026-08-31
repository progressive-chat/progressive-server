# Step 105 — "fix: double join over federation" (Conduit `9109cb4`)

Source: [`timokoesters/conduit@9109cb4`](https://github.com/timokoesters/conduit/commit/9109cb4) (2020-10)

## What changed vs step 104

| Rust change | C++ translation |
|---|---|
| Fix: avoid double-joining a room over federation when the local and remote both have the join event. | **Translated** — Our federation join (step 31) checks for existing membership before attempting join. |

## Implementation details

- Our federation join (step 31) checks for existing membership before attempting join.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
