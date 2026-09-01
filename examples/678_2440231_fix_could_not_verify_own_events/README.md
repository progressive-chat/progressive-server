# Step 678 — "fix: could not verify own events" (Conduit `2440231`)

Source: [`timokoesters/conduit@2440231`](https://github.com/timokoesters/conduit/commit/2440231) (2023-07)

## What changed vs step 677

| Rust change | C++ translation |
|---|---|
| Fix: could not verify own events. Event verification for locally created events. 1 file changed. | **Translated** — Our event verification (step 337) handles own events. This fixes the Rust version. |

## Implementation details

- Our event verification (step 337) handles own events. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
