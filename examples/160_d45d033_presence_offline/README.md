# Step 160 — "fix: send presence updates when going offline" (Conduit `d45d033`)

Source: [`timokoesters/conduit@d45d033`](https://github.com/timokoesters/conduit/commit/d45d033) (2021-01)

## What changed vs step 159

| Rust change | C++ translation |
|---|---|
| Fix: send presence updates when going offline. When a user disconnects, send `m.presence: offline` to all rooms they're in. | **No-op for us** — We don't have presence yet (gap from `ee0d6940` 2020 commit). |

## Implementation details

- We don't have presence yet (gap from `ee0d6940` 2020 commit).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
