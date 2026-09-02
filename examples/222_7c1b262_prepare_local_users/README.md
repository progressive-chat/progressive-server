# Step 222 — "Prepare to add an option to list local user accounts from your homeserver" (Conduit `7c1b262`)

Source: [`timokoesters/conduit@7c1b262`](https://github.com/timokoesters/conduit/commit/7c1b262) (2021-12-24)

## What changed vs step 221

| Rust change | C++ translation |
|---|---|
| **Prepare local user accounts list** | **Translated** — Prepare local users |

## Implementation details

1. **Prepare local users** — Prepare to add an option to list local user accounts from your homeserver

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
