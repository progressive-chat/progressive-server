# Step 567 — "Do not return true for is_guest on whoami for appservice users" (Conduit `2d0fddd`)

Source: [`timokoesters/conduit@2d0fddd`](https://github.com/timokoesters/conduit/commit/2d0fddd) (2022-10)

## What changed vs step 566

| Rust change | C++ translation |
|---|---|
| Do not return true for is_guest on whoami for appservice users. Appservice users are not guests. | **Translated** — Our whoami (step 10) returns is_guest. This fixes for appservice users. |

## Implementation details

- Our whoami (step 10) returns is_guest. This fixes for appservice users.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
