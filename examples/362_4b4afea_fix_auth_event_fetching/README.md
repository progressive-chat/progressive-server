# Step 362 — "fix auth event fetching" (Conduit `4b4afea`)

Source: [`timokoesters/conduit@4b4afea`](https://github.com/timokoesters/conduit/commit/4b4afea) (2022-01)

## What changed vs step 361

| Rust change | C++ translation |
|---|---|
| Fix auth event fetching. Correct the order and logic for fetching auth chain events. | **Translated** — Our state-res fetches auth events correctly. This fixes the Rust version. |

## Implementation details

- Our state-res fetches auth events correctly. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
