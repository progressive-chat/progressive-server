# Step 269 — "Bump ruma" (Conduit `5be5c9e`)

Source: [`timokoesters/conduit@5be5c9e`](https://github.com/timokoesters/conduit/commit/5be5c9e) (2021-04)

## What changed vs step 268

| Rust change | C++ translation |
|---|---|
| Bump ruma. Dependency version bump. | **Skipped** — Rust dependency bump. |

## Implementation details

- Rust dependency bump.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
