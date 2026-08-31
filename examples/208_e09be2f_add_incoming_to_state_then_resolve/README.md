# Step 208 — "Add incoming event to the current room state then resolve" (Conduit `e09be2f`)

Source: [`timokoesters/conduit@e09be2f`](https://github.com/timokoesters/conduit/commit/e09be2f) (2021-02)

## What changed vs step 207

| Rust change | C++ translation |
|---|---|
| Add incoming event to the current room state then resolve. The incoming event is first added to state, then resolution runs. | **Translated** — Our state-res follows the same pattern: add event, then resolve. |

## Implementation details

- Our state-res follows the same pattern: add event, then resolve.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
