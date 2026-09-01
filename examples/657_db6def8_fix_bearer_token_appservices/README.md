# Step 657 — "fix: send correct bearer token to appservices" (Conduit `db6def8`)

Source: [`timokoesters/conduit@db6def8`](https://github.com/timokoesters/conduit/commit/db6def8) (2023-06)

## What changed vs step 656

| Rust change | C++ translation |
|---|---|
| Fix: send correct bearer token to appservices. Appservice authentication token fix. | **Translated** — Our appservice (step 96) uses bearer tokens. This fixes the token sent. |

## Implementation details

- Our appservice (step 96) uses bearer tokens. This fixes the token sent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
