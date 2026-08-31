# Step 537 — "fix: workaround for missing avatars on element and rooms becoming historical" (Conduit `31d1801`)

Source: [`timokoesters/conduit@31d1801`](https://github.com/timokoesters/conduit/commit/31d1801) (2022-10)

## What changed vs step 536

| Rust change | C++ translation |
|---|---|
| Fix: workaround for missing avatars on element and rooms becoming historical. Element compatibility and room state fix. 2 files changed. | **Translated** — Our avatars (step 14) and room state (step 83) work. This fixes Element compatibility in Rust. |

## Implementation details

- Our avatars (step 14) and room state (step 83) work. This fixes Element compatibility in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
