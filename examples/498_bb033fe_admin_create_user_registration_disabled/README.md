# Step 498 — "added a command to the admin bot to create a new user, even with registration disabled" (Conduit `bb033fe`)

Source: [`timokoesters/conduit@bb033fe`](https://github.com/timokoesters/conduit/commit/bb033fe) (2022-05)

## What changed vs step 497

| Rust change | C++ translation |
|---|---|
| Added a command to the admin bot to create a new user, even with registration disabled. Admin user creation override. 2 files changed. | **Translated** — Our admin commands (step 60) don't have this. Adds user creation when registration is disabled. |

## Implementation details

- Our admin commands (step 60) don't have this. Adds user creation when registration is disabled.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
