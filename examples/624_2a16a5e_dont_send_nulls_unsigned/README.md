# Step 624 — "fix: don't send nulls as unsigned content" (Conduit `2a16a5e`)

Source: [`timokoesters/conduit@2a16a5e`](https://github.com/timokoesters/conduit/commit/2a16a5e) (2023-03)

## What changed vs step 623

| Rust change | C++ translation |
|---|---|
| Fix: don't send nulls as unsigned content. Fix null handling in unsigned field. 1 file changed. | **Translated** — Our unsigned content (step 8) handles nulls. This fixes the Rust version. |

## Implementation details

- Our unsigned content (step 8) handles nulls. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
