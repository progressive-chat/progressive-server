# Step 518 — "Refactor appservices, pusher, timeline, transactionids, users" (Conduit `f56424b`)

Source: [`timokoesters/conduit@f56424b`](https://github.com/timokoesters/conduit/commit/f56424b) (2022-10)

## What changed vs step 517

| Rust change | C++ translation |
|---|---|
| Refactor appservices, pusher, timeline, transactionids, users. Major refactor of core services. 18 files changed. | **Translated** — Our appservice (step 96), pusher (steps 186-187), timeline (step 6) cover this. |

## Implementation details

- Our appservice (step 96), pusher (steps 186-187), timeline (step 6) cover this.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
