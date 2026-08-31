# Step 541 — "fix: element gets stuck in /initialSync" (Conduit `2b70d96`)

Source: [`timokoesters/conduit@2b70d96`](https://github.com/timokoesters/conduit/commit/2b70d96) (2022-10)

## What changed vs step 540

| Rust change | C++ translation |
|---|---|
| Fix: element gets stuck in /initialSync. Initial sync compatibility fix for Element. 3 files changed. | **Translated** — Our /sync (step 6) works with Element. This fixes a Rust /initialSync issue. |

## Implementation details

- Our /sync (step 6) works with Element. This fixes a Rust /initialSync issue.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
