# Step 97 — "Reduce media ID length from 256 to 32" (Conduit `26e200e`)

Source: [`timokoesters/conduit@26e200e`](https://github.com/timokoesters/conduit/commit/26e200e) (2020-09)

## What changed vs step 96

| Rust change | C++ translation |
|---|---|
| Reduces the media ID length from 256 to 32 characters. Shorter IDs are easier to handle in URLs. | **Translated** — Our step 14 (`821c608c_media`) uses `MXC_LENGTH = 256`. The 32-char version is simpler but functionally equivalent. |

## Implementation details

- Our step 14 (`821c608c_media`) uses `MXC_LENGTH = 256`. The 32-char version is simpler but functionally equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
