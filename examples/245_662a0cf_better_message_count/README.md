# Step 245 — "improvement: better and more efficient message count calculation" (Conduit `662a0cf`)

Source: [`timokoesters/conduit@662a0cf`](https://github.com/timokoesters/conduit/commit/662a0cf) (2021-04)

## What changed vs step 244

| Rust change | C++ translation |
|---|---|
| Improvement: better and more efficient message count calculation. Optimizes unread message counts. 7 files changed. | **Translated** — Our unread count (step 187 `7312462_pusher_rules_unread`) calculates counts. This optimizes it. |

## Implementation details

- Our unread count (step 187 `7312462_pusher_rules_unread`) calculates counts. This optimizes it.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
