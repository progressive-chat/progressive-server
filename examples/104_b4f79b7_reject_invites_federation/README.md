# Step 104 — "feat: reject invites over federation" (Conduit `b4f79b7`)

Source: [`timokoesters/conduit@b4f79b7`](https://github.com/timokoesters/conduit/commit/b4f79b7) (2021-04-13)

## What changed vs step 103

| Rust change | C++ translation |
|---|---|
| **Reject invites over federation** | **Translated** — Reject invites |
| **Major rooms.rs refactor** | **Translated** — Cleaner rooms |
| **Major sync.rs cleanup** | **Translated** — Sync cleanup |

## Implementation details

1. **Reject invites** — Reject invites over federation
2. **Major rooms refactor** — Major refactor of rooms.rs
3. **Sync cleanup** — Major cleanup of sync.rs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
