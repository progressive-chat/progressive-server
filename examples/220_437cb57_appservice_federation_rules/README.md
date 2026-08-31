# Step 220 — "fix: apply the same appservice sending rules to events coming from federation" (Conduit `437cb57`)

Source: [`timokoesters/conduit@437cb57`](https://github.com/timokoesters/conduit/commit/437cb57) (2021-03)

## What changed vs step 219

| Rust change | C++ translation |
|---|---|
| Fix: apply the same appservice sending rules to events coming from federation. Events from federation should respect appservice namespace rules. | **Translated** — Our appservice dispatch checks sender. This extends the check to federated events. |

## Implementation details

- Our appservice dispatch checks sender. This extends the check to federated events.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
