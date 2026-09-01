# Step 656 — "fix: /context for element android. start and end must be set even with limit=0" (Conduit `49a0f3a`)

Source: [`timokoesters/conduit@49a0f3a`](https://github.com/timokoesters/conduit/commit/49a0f3a) (2023-06)

## What changed vs step 655

| Rust change | C++ translation |
|---|---|
| Fix: /context for element android. start and end must be set even with limit=0. Context endpoint fix. 4 files changed. | **Translated** — Our /context (step 10) handles start/end. This fixes the Rust version for Element Android. |

## Implementation details

- Our /context (step 10) handles start/end. This fixes the Rust version for Element Android.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
