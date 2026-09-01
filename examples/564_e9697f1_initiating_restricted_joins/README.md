# Step 564 — "Handle initiating restricted joins over federation" (Conduit `e9697f1`)

Source: [`timokoesters/conduit@e9697f1`](https://github.com/timokoesters/conduit/commit/e9697f1) (2022-10)

## What changed vs step 563

| Rust change | C++ translation |
|---|---|
| Handle initiating restricted joins over federation. Restricted room join support. 1 file changed. | **Translated** — Our restricted joins (step 25) work. This adds federation initiation. |

## Implementation details

- Our restricted joins (step 25) work. This adds federation initiation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
