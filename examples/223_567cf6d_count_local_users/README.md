# Step 223 — "Add command count_local_users to database/rooms.rs" (Conduit `567cf6d`)

Source: [`timokoesters/conduit@567cf6d`](https://github.com/timokoesters/conduit/commit/567cf6d) (2021-12-25)

## What changed vs step 222

| Rust change | C++ translation |
|---|---|
| **count_local_users command** | **Translated** — count_local_users |

## Implementation details

1. **count_local_users** — Add command count_local_users to database/rooms.rs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
