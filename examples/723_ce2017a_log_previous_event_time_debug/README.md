# Step 723 — "log handling previous event time as debug" (Conduit `ce2017a`)

Source: [`timokoesters/conduit@ce2017a`](https://github.com/timokoesters/conduit/commit/ce2017a) (2023-08)

## What changed vs step 722

| Rust change | C++ translation |
|---|---|
| Log handling previous event time as debug. Debug logging for prev_event timing. 1 file changed. | **Translated** — Our prev_event handling (step 29) logs. This adds debug timing. |

## Implementation details

- Our prev_event handling (step 29) logs. This adds debug timing.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
