# Step 398 — "improvement: lower default pdu cache capacity" (Conduit `03b1743`)

Source: [`timokoesters/conduit@03b1743`](https://github.com/timokoesters/conduit/commit/03b1743) (2022-01)

## What changed vs step 397

| Rust change | C++ translation |
|---|---|
| Improvement: lower default pdu cache capacity. Reduce memory usage default. | **Translated** — Our PDU cache (step 320/382) has a capacity. This lowers the default. |

## Implementation details

- Our PDU cache (step 320/382) has a capacity. This lowers the default.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
