# Step 86 — "fix: remove well-known" (Conduit `005e00e`)

Source: [`timokoesters/conduit@005e00e`](https://github.com/timokoesters/conduit/commit/005e00e) (2020-09)

## What changed vs step 85

| Rust change | C++ translation |
|---|---|
| Removes the well-known lookup from `send_request` (it was returning a static `privacytools.io` value). | Our `send_request` doesn't have the well-known lookup either — it builds the URL directly from the destination. |

## Implementation details

- Our `send_request` doesn't have the well-known lookup either — it builds the URL directly from the destination.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
