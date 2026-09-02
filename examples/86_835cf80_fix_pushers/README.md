# Step 86 — "fix: pushers" (Conduit `835cf80`)

Source: [`timokoesters/conduit@835cf80`](https://github.com/timokoesters/conduit/commit/835cf80) (2021-02-11)

## What changed vs step 85

| Rust change | C++ translation |
|---|---|
| **Fix pushers** | **Translated** — Pusher fixes |
| **Major pusher refactor** | **Translated** — Pusher database refactor |

## Implementation details

1. **Pusher fixes** — Fixed pusher code
2. **Pusher database refactor** — Major refactor of pusher database
3. **Sending improvements** — Improved pusher sending

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
