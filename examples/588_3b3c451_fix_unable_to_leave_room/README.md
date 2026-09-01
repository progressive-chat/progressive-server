# Step 588 — "fix: unable to leave room" (Conduit `3b3c451`)

Source: [`timokoesters/conduit@3b3c451`](https://github.com/timokoesters/conduit/commit/3b3c451) (2022-11)

## What changed vs step 587

| Rust change | C++ translation |
|---|---|
| Fix: unable to leave room. Room leave functionality fix. 1 file changed. | **Translated** — Our leave (step 16) works. This fixes a Rust leave bug. |

## Implementation details

- Our leave (step 16) works. This fixes a Rust leave bug.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
