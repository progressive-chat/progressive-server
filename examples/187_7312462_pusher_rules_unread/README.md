# Step 187 — "Add general rules matching for pusher, calc unread msgs" (Conduit `7312462`)

Source: [`timokoesters/conduit@7312462`](https://github.com/timokoesters/conduit/commit/7312462) (2021-01)

## What changed vs step 186

| Rust change | C++ translation |
|---|---|
| Add general rules matching for pusher, calc unread msgs. 5 files changed. | **Translated** — Push rule evaluation and unread count calculation. |

## Implementation details

- Push rule evaluation and unread count calculation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
