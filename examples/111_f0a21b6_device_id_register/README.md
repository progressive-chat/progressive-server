# Step 111 — "fix: use device_id when registering" (Conduit `f0a21b6`)

Source: [`timokoesters/conduit@f0a21b6`](https://github.com/timokoesters/conduit/commit/f0a21b6) (2020-10)

## What changed vs step 110

| Rust change | C++ translation |
|---|---|
| Fix: use the client-provided `device_id` when registering a user (instead of always generating a random one). | **Translated** — Our register handler (step 6) accepts an optional `device_id` and uses it if provided. |

## Implementation details

- Our register handler (step 6) accepts an optional `device_id` and uses it if provided.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
