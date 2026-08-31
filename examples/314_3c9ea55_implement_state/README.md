# Step 314 — "feat: /state" (Conduit `3c9ea55`)

Source: [`timokoesters/conduit@3c9ea55`](https://github.com/timokoesters/conduit/commit/3c9ea55) (2021-06)

## What changed vs step 313

| Rust change | C++ translation |
|---|---|
| Feat: /state endpoint. Get current room state events. 2 files changed. NEW FEATURE. | **Translated** — We don't have /state endpoint yet. This adds the room state API. |

## Implementation details

- We don't have /state endpoint yet. This adds the room state API.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
