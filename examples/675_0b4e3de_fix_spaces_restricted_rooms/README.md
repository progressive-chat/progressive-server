# Step 675 — "fix: spaces with restricted rooms" (Conduit `0b4e3de`)

Source: [`timokoesters/conduit@0b4e3de`](https://github.com/timokoesters/conduit/commit/0b4e3de) (2023-07)

## What changed vs step 674

| Rust change | C++ translation |
|---|---|
| Fix: spaces with restricted rooms. Space hierarchy compatibility with restricted rooms. | **Translated** — Follows step 667 (space hierarchies). Fixes restricted room handling in spaces. |

## Implementation details

- Follows step 667 (space hierarchies). Fixes restricted room handling in spaces.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
