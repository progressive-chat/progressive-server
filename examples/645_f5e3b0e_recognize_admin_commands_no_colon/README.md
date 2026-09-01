# Step 645 — "Recognize admin commands without : after tag Very useful since many Matrix clients don't insert : after user tags" (Conduit `f5e3b0e`)

Source: [`timokoesters/conduit@f5e3b0e`](https://github.com/timokoesters/conduit/commit/f5e3b0e) (2023-05)

## What changed vs step 644

| Rust change | C++ translation |
|---|---|
| Recognize admin commands without : after tag. Many Matrix clients don't insert : after user tags. 1 file changed. | **Translated** — Our admin commands (step 60) parse tags. This adds support for missing colon. |

## Implementation details

- Our admin commands (step 60) parse tags. This adds support for missing colon.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
