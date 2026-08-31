# Step 244 — "fix: show warning for invalid user ids" (Conduit `1dc8589`)

Source: [`timokoesters/conduit@1dc8589`](https://github.com/timokoesters/conduit/commit/1dc8589) (2021-04)

## What changed vs step 243

| Rust change | C++ translation |
|---|---|
| Fix: show warning for invalid user IDs. Validates user ID format (@user:server). | **Translated** — Our user ID validation is in auth handlers. This adds warnings for malformed IDs. |

## Implementation details

- Our user ID validation is in auth handlers. This adds warnings for malformed IDs.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
