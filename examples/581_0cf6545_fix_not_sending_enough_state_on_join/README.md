# Step 581 — "fix: not sending enough state on join" (Conduit `0cf6545`)

Source: [`timokoesters/conduit@0cf6545`](https://github.com/timokoesters/conduit/commit/0cf6545) (2022-10)

## What changed vs step 580

| Rust change | C++ translation |
|---|---|
| Fix: not sending enough state on join. Join response missing state events. 3 files changed. | **Translated** — Our join (step 25, 93) sends full state. This fixes the Rust version. |

## Implementation details

- Our join (step 25, 93) sends full state. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
