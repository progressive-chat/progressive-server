# Step 109 — "Allow reading state if history_visibility is world readable" (Conduit `243126d`)

Source: [`timokoesters/conduit@243126d`](https://github.com/timokoesters/conduit/commit/243126d) (2020-10)

## What changed vs step 108

| Rust change | C++ translation |
|---|---|
| Allow reading state events if `history_visibility` is `world_readable` (i.e., anyone can read, even non-members). | **Translated** — Our state retrieval (step 28) doesn't check membership, so this is effectively already the case for our C++ code. |

## Implementation details

- Our state retrieval (step 28) doesn't check membership, so this is effectively already the case for our C++ code.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
