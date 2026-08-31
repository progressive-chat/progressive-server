# Step 164 — "Update state-res, use the new Event trait" (Conduit `9e83d2b`)

Source: [`timokoesters/conduit@9e83d2b`](https://github.com/timokoesters/conduit/commit/9e83d2b) (2021-01)

## What changed vs step 163

| Rust change | C++ translation |
|---|---|
| Update state-res, use the new Event trait. 11 files changed, mostly type updates. | **Skipped** — ruma update + Rust type trait. No direct C++ equivalent. |

## Implementation details

- ruma update + Rust type trait. No direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
