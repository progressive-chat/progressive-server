# Step 492 — "Send PDU to appservice if state_key is their user ID" (Conduit `9046223`)

Source: [`timokoesters/conduit@9046223`](https://github.com/timokoesters/conduit/commit/9046223) (2022-04)

## What changed vs step 491

| Rust change | C++ translation |
|---|---|
| Send PDU to appservice if state_key is their user ID. Appservice state event routing. 1 file changed. | **Translated** — Our appservice (step 96) routes events. This adds state_key-based routing. |

## Implementation details

- Our appservice (step 96) routes events. This adds state_key-based routing.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
