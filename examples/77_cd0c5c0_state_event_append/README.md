# Step 77 — "Append state event that pass resolution to DB" (Conduit `cd0c5c0`)

Source: [`timokoesters/conduit@cd0c5c0`](https://github.com/timokoesters/conduit/commit/cd0c5c0) (2021-01-29)

## What changed vs step 76

| Rust change | C++ translation |
|---|---|
| **Append state event that pass resolution to DB** | **Translated** — State events appended after resolution |
| **Tokio 1.1 update** | **N/A** — Rust-only dependency update |
| **Major server_server refactor** | **Translated** — State event handling |

## Implementation details

1. **State event append** — Append state events that pass resolution to DB
2. **Server server refactor** — Major refactor of state event handling

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
