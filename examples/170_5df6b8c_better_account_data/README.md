# Step 170 — "improvement: better account data implementation" (Conduit `5df6b8c`)

Source: [`timokoesters/conduit@5df6b8c`](https://github.com/timokoesters/conduit/commit/5df6b8c) (2021-07-30)

## What changed vs step 169

| Rust change | C++ translation |
|---|---|
| **Better account data** | **Translated** — Better account data |
| **Major account_data refactor** | **Translated** — Cleaner account_data code |
| **Major pusher refactor** | **Translated** — Cleaner pusher code |

## Implementation details

1. **Better account data** — Better account data implementation
2. **Major account_data refactor** — Major refactor of account_data.rs
3. **Major pusher refactor** — Major refactor of pusher.rs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
