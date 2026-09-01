# Step 622 — "Allow backfilling create event itself" (Conduit `d39003f`)

Source: [`timokoesters/conduit@d39003f`](https://github.com/timokoesters/conduit/commit/d39003f) (2023-03)

## What changed vs step 621

| Rust change | C++ translation |
|---|---|
| Allow backfilling create event itself. Duplicate of step 620. | **Translated** — Duplicate of step 620/621 — backfill create event. |

## Implementation details

- Duplicate of step 620/621 — backfill create event.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
