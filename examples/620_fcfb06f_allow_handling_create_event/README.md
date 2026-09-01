# Step 620 — "fix: allow handling create event itself" (Conduit `fcfb06f`)

Source: [`timokoesters/conduit@fcfb06f`](https://github.com/timokoesters/conduit/commit/fcfb06f) (2023-03)

## What changed vs step 619

| Rust change | C++ translation |
|---|---|
| Fix: allow handling create event itself. Room create event handling in backfill. 1 file changed. | **Translated** — Related to backfill (steps 618-619). Handles create event. |

## Implementation details

- Related to backfill (steps 618-619). Handles create event.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
