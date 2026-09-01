# Step 713 — "fix: spaces with restricted rooms" (Conduit `0b4e3de`)

Source: [`timokoesters/conduit@0b4e3de`](https://github.com/timokoesters/conduit/commit/0b4e3de) (2023-07)

## What changed vs step 712

| Rust change | C++ translation |
|---|---|
| Duplicate of step 675 (fix spaces with restricted rooms). | **Skipped** — Duplicate of step 675. |

## Implementation details

- Duplicate of step 675.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
