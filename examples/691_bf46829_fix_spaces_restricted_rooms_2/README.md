# Step 691 — "fix: spaces with restricted rooms" (Conduit `bf46829`)

Source: [`timokoesters/conduit@bf46829`](https://github.com/timokoesters/conduit/commit/bf46829) (2023-07)

## What changed vs step 690

| Rust change | C++ translation |
|---|---|
| Fix: spaces with restricted rooms. Duplicate of step 675. | **Translated** — Duplicate of step 675 — fixes spaces + restricted rooms. |

## Implementation details

- Duplicate of step 675 — fixes spaces + restricted rooms.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
