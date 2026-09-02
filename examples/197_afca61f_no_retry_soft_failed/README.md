# Step 197 — "fix: don't retry soft failed events" (Conduit `afca61f`)

Source: [`timokoesters/conduit@afca61f`](https://github.com/timokoesters/conduit/commit/afca61f) (2021-08-28)

## What changed vs step 196

| Rust change | C++ translation |
|---|---|
| **Don't retry soft failed events** | **Translated** — No retry soft failed |
| **Major sync refactor** | **Translated** — Cleaner sync code |
| **Major rooms refactor** | **Translated** — Cleaner rooms code |

## Implementation details

1. **No retry soft failed** — Don't retry soft failed events
2. **Major sync refactor** — Major refactor of sync.rs
3. **Major rooms refactor** — Major refactor of rooms.rs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
