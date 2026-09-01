# Step 40 — "Reduce media ID length from 256 to 32" (Conduit `26e200e`)

Source: [`timokoesters/conduit@26e200e`](https://github.com/timokoesters/conduit/commit/26e200e) (2020-09-25)

## What changed vs step 39

| Rust change | C++ translation |
|---|---|
| **Reduce `MXC_LENGTH` from 256 to 32** | **Translated** — Updated `MXC_LENGTH` constant in media handling |

## Implementation details

- Reduced `MXC_LENGTH` constant from 256 to 32 characters
- This matches Synapse's media ID length (25) and prevents filesystem path length issues (most filesystems limit paths to 255 bytes)
- Makes it possible for clients to download media with the ID included in the filename

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
