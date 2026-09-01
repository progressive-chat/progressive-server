# Step 568 — "Raise 404 when room doesn't exist" (Conduit `6fd39ae`)

Source: [`timokoesters/conduit@6fd39ae`](https://github.com/timokoesters/conduit/commit/6fd39ae) (2022-10)

## What changed vs step 567

| Rust change | C++ translation |
|---|---|
| Raise 404 when room doesn't exist. Proper 404 for missing rooms. 1 file changed. | **Translated** — Our room endpoints return 404. This ensures the Rust version does. |

## Implementation details

- Our room endpoints return 404. This ensures the Rust version does.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
