# Step 154 — "improvement: pdu cache, /sync cache" (Conduit `05821d6`)

Source: [`timokoesters/conduit@05821d6`](https://github.com/timokoesters/conduit/commit/05821d6) (2021-06-30)

## What changed vs step 153

| Rust change | C++ translation |
|---|---|
| **PDU cache** | **Translated** — PDU cache |
| **/sync cache** | **Translated** — /sync cache |
| **Major directory refactor** | **Translated** — Cleaner directory code |
| **Major sync refactor** | **Translated** — Cleaner sync code |

## Implementation details

1. **PDU cache** — Add PDU cache
2. **/sync cache** — Add /sync cache
3. **Major directory refactor** — Major refactor of directory code
4. **Major sync refactor** — Major refactor of sync code

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
