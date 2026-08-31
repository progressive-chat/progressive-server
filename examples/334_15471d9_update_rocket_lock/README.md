# Step 334 — "update rocket and lock" (Conduit `15471d9`)

Source: [`timokoesters/conduit@15471d9`](https://github.com/timokoesters/conduit/commit/15471d9) (2021-07)

## What changed vs step 333

| Rust change | C++ translation |
|---|---|
| Update rocket and lock. Web framework and dependency updates. 4 files changed. | **Skipped** — Rust Rocket framework update — our httplib is different. |

## Implementation details

- Rust Rocket framework update — our httplib is different.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
