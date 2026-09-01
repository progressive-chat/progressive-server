# Step 726 — "Back off from more events, don't retry auth events" (Conduit `9b55ce9`)

Source: [`timokoesters/conduit@9b55ce9`](https://github.com/timokoesters/conduit/commit/9b55ce9) (2023-08)

## What changed vs step 725

| Rust change | C++ translation |
|---|---|
| Back off from more events, don't retry auth events. Event retry backoff logic. 1 file changed. | **Translated** — Our federation (step 29) has retry logic. This adds backoff for auth events. |

## Implementation details

- Our federation (step 29) has retry logic. This adds backoff for auth events.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
