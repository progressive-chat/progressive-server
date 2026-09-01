# Step 579 — "fix: element android did not reset notification counts" (Conduit `02dd3d3`)

Source: [`timokoesters/conduit@02dd3d3`](https://github.com/timokoesters/conduit/commit/02dd3d3) (2022-10)

## What changed vs step 578

| Rust change | C++ translation |
|---|---|
| Fix: element android did not reset notification counts. Push notification count fix for Element Android. 7 files changed. | **Translated** — Our push notifications (steps 186-187) handle counts. This fixes a specific Element Android issue. |

## Implementation details

- Our push notifications (steps 186-187) handle counts. This fixes a specific Element Android issue.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
