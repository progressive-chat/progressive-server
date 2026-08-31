# Step 110 — "Use conduit.rs server in the README shield" (Conduit `f6f15d9`)

Source: [`timokoesters/conduit@f6f15d9`](https://github.com/timokoesters/conduit/commit/f6f15d9) (2020-10)

## What changed vs step 109

| Rust change | C++ translation |
|---|---|
| Update the README shield to point to `conduit.rs` server instead of the old test server. | **No-op for us** — Our README has its own shields. N/A for our translation. |

## Implementation details

- Our README has its own shields. N/A for our translation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
