# Step 628 — "fix: don't unwrap server keys" (Conduit `bde4880`)

Source: [`timokoesters/conduit@bde4880`](https://github.com/timokoesters/conduit/commit/bde4880) (2023-03)

## What changed vs step 627

| Rust change | C++ translation |
|---|---|
| Fix: don't unwrap server keys. Handle missing server keys gracefully. 1 file changed. | **Translated** — Our key fetching (step 8) handles missing keys. This prevents unwrap panic. |

## Implementation details

- Our key fetching (step 8) handles missing keys. This prevents unwrap panic.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
