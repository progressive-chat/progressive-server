# Step 639 — "Use the ruma methods for managing rulesets" (Conduit `4635644`)

Source: [`timokoesters/conduit@4635644`](https://github.com/timokoesters/conduit/commit/4635644) (2023-03)

## What changed vs step 638

| Rust change | C++ translation |
|---|---|
| Use the ruma methods for managing rulesets. Push rule management via Ruma library. 1 file changed. | **Translated** — Our push rules (steps 181-182, 186-187) manage rulesets. This uses library methods. |

## Implementation details

- Our push rules (steps 181-182, 186-187) manage rulesets. This uses library methods.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
