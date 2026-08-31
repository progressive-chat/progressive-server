# Step 538 — "fix: state for left rooms" (Conduit `68227c0`)

Source: [`timokoesters/conduit@68227c0`](https://github.com/timokoesters/conduit/commit/68227c0) (2022-10)

## What changed vs step 537

| Rust change | C++ translation |
|---|---|
| Fix: state for left rooms. Handle room state correctly after user leaves. | **Translated** — Our state resolution (step 83) handles left rooms. This fixes the Rust version. |

## Implementation details

- Our state resolution (step 83) handles left rooms. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
