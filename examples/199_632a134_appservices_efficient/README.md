# Step 199 — "fix: make appservices more efficient" (Conduit `632a134`)

Source: [`timokoesters/conduit@632a134`](https://github.com/timokoesters/conduit/commit/632a134) (2021-08-29)

## What changed vs step 198

| Rust change | C++ translation |
|---|---|
| **Appservices more efficient** | **Translated** — Appservices efficiency |
| **Major rooms refactor** | **Translated** — Cleaner rooms code |
| **Major server_server refactor** | **Translated** — Cleaner server_server |

## Implementation details

1. **Appservices efficiency** — Make appservices more efficient
2. **Major rooms refactor** — Major refactor of rooms.rs
3. **Major server_server refactor** — Major refactor of server_server

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
