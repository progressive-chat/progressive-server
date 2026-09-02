# Step 103 — "fix: membership deserializing" (Conduit `84f4ce7`)

Source: [`timokoesters/conduit@84f4ce7`](https://github.com/timokoesters/conduit/commit/84f4ce7) (2021-04-09)

## What changed vs step 102

| Rust change | C++ translation |
|---|---|
| **Membership deserializing fix** | **Translated** — Membership deserialize fix |
| **Major rooms.rs refactor** | **Translated** — Cleaner rooms code |
| **Utils improvements** | **Translated** — Better utils |

## Implementation details

1. **Membership deserializing** — Fix membership deserializing
2. **Major rooms refactor** — Major refactor of rooms.rs
3. **Utils improvements** — Better utils

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
