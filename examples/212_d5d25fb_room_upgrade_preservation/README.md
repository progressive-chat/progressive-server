# Step 212 — "Preserve all m.room.create entries when performing room upgrades" (Conduit `d5d25fb`)

Source: [`timokoesters/conduit@d5d25fb`](https://github.com/timokoesters/conduit/commit/d5d25fb) (2021-10-24)

## What changed vs step 211

| Rust change | C++ translation |
|---|---|
| **Preserve m.room.create entries on room upgrade** | **Translated** — Room upgrade preservation |

## Implementation details

1. **Room upgrade preservation** — Preserve all m.room.create entries when performing room upgrades

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
