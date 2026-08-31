# Step 302 — "fix: is_direct for locally invited users" (Conduit `deacdf6`)

Source: [`timokoesters/conduit@deacdf6`](https://github.com/timokoesters/conduit/commit/deacdf6) (2021-05)

## What changed vs step 301

| Rust change | C++ translation |
|---|---|
| Fix: is_direct for locally invited users. Direct message flag for DM rooms created via local invite. | **Translated** — Our DM handling (step 10) sets is_direct. This fixes the flag for local invites. |

## Implementation details

- Our DM handling (step 10) sets is_direct. This fixes the flag for local invites.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
