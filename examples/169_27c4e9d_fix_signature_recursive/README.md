# Step 169 — "Fix signature/hash checks, fetch recursive auth events" (Conduit `27c4e9d`)

Source: [`timokoesters/conduit@27c4e9d`](https://github.com/timokoesters/conduit/commit/27c4e9d) (2021-01)

## What changed vs step 168

| Rust change | C++ translation |
|---|---|
| Fix signature/hash checks, fetch recursive auth events. The `/send` flow now properly verifies signatures and fetches all auth chain events. | **Translated** — Our `crypto::sign_json` and `verify` (server side) handle signatures. Auth event fetching is in step 83. |

## Implementation details

- Our `crypto::sign_json` and `verify` (server side) handle signatures. Auth event fetching is in step 83.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
