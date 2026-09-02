# Step 190 — "improvement: faster incoming transaction handling" (Conduit `46d8a46`)

Source: [`timokoesters/conduit@46d8a46`](https://github.com/timokoesters/conduit/commit/46d8a46) (2021-08-19)

## What changed vs step 189

| Rust change | C++ translation |
|---|---|
| **Faster incoming transaction** | **Translated** — Faster incoming txn |
| **Major server_server refactor** | **Translated** — Cleaner server_server |
| **Major uiaa.rs refactor** | **Translated** — Cleaner uiaa |

## Implementation details

1. **Faster incoming txn** — Faster incoming transaction handling
2. **Major server_server refactor** — Major refactor of server_server
3. **Major uiaa refactor** — Major refactor of uiaa.rs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
