# Step 183 — "Resolved state is set as the current room state on incoming events" (Conduit `894b6ef`)

Source: [`timokoesters/conduit@894b6ef`](https://github.com/timokoesters/conduit/commit/894b6ef) (2021-01)

## What changed vs step 182

| Rust change | C++ translation |
|---|---|
| Resolved state is set as the current room state on incoming events. After state resolution succeeds, the resolved state becomes the room's current state. | **Translated** — Our state-res (step 83) does this — the resolved state is written as current state. |

## Implementation details

- Our state-res (step 83) does this — the resolved state is written as current state.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
