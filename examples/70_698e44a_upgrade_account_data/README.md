# Step 70 — "Fix /upgrade account data problems" (Conduit `698e44a`)

Source: [`timokoesters/conduit@698e44a`](https://github.com/timokoesters/conduit/commit/698e44a) (2020-09)

## What changed vs step 69

| Rust change | C++ translation |
|---|---|
| Fix: account data is properly migrated during room upgrade. | **Covered** — folded into our step 25 (`df55e8ed_room_upgrade`) implementation. |

## Implementation details

- **Covered** — folded into our step 25 (`df55e8ed_room_upgrade`) implementation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
