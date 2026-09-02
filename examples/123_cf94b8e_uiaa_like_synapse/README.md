# Step 123 — "improvement: uiaa works like in synapse" (Conduit `cf94b8e`)

Source: [`timokoesters/conduit@cf94b8e`](https://github.com/timokoesters/conduit/commit/cf94b8e) (2021-05-04)

## What changed vs step 122

| Rust change | C++ translation |
|---|---|
| **UIAA works like in synapse** | **Translated** — UIAA synapse-like |
| **Major uiaa.rs refactor** | **Translated** — UIAA database refactor |
| **Major directory.rs refactor** | **Translated** — Cleaner directory code |
| **Major ruma_wrapper refactor** | **Translated** — Cleaner ruma_wrapper |

## Implementation details

1. **UIAA synapse-like** — UIAA works like in synapse
2. **Major UIAA refactor** — Major refactor of uiaa database
3. **Major directory refactor** — Major refactor of directory code
4. **Major ruma_wrapper refactor** — Major refactor of ruma_wrapper

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
