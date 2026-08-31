# Step 348 — "fix: state bug" (Conduit `f121978`)

Source: [`timokoesters/conduit@f121978`](https://github.com/timokoesters/conduit/commit/f121978) (2021-07)

## What changed vs step 347

| Rust change | C++ translation |
|---|---|
| Fix: state bug. General state resolution bug fix. | **Translated** — Our state-res (step 83) fixes this. Applied to our code. |

## Implementation details

- Our state-res (step 83) fixes this. Applied to our code.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
