# Step 57 — "fix: send state in /sync" (Conduit `f12fbca`)

Source: [`timokoesters/conduit@f12fbca`](https://github.com/timokoesters/conduit/commit/f12fbca) (2020-12-22)

## What changed vs step 56

| Rust change | C++ translation |
|---|---|
| **Send state events in /sync** | **Translated** — State events included in sync |
| **Fix membership changes display** | **Translated** — Proper membership state in sync |
| **Send state in initial sync** | **Translated** — State sent in initial sync |

## Implementation details

1. **State events in sync** — `/sync` now includes state events
2. **Membership state fix** — Proper handling of membership changes
3. **Initial sync state** — State sent in initial sync responses

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
