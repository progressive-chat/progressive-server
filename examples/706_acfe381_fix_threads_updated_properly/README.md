# Step 706 — "fix: threads get updated properly" (Conduit `acfe381`)

Source: [`timokoesters/conduit@acfe381`](https://github.com/timokoesters/conduit/commit/acfe381) (2023-07)

## What changed vs step 705

| Rust change | C++ translation |
|---|---|
| Fix: threads get updated properly. Thread (MSC3440) update fixes. 9 files changed. | **Translated** — Follows step 654/658/689/690 (threads). This fixes thread updates. |

## Implementation details

- Follows step 654/658/689/690 (threads). This fixes thread updates.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
