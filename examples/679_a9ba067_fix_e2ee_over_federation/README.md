# Step 679 — "fix: e2ee over federation" (Conduit `a9ba067`)

Source: [`timokoesters/conduit@a9ba067`](https://github.com/timokoesters/conduit/commit/a9ba067) (2023-07)

## What changed vs step 678

| Rust change | C++ translation |
|---|---|
| Fix: e2ee over federation. End-to-end encryption federation fixes. 7 files changed. MAJOR. | **Translated** — Our E2EE (step 337, 550) is local. This adds federation E2EE support. |

## Implementation details

- Our E2EE (step 337, 550) is local. This adds federation E2EE support.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
