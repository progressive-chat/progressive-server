# Step 181 — "feature: push rule settings" (Conduit `a119d85`)

Source: [`timokoesters/conduit@a119d85`](https://github.com/timokoesters/conduit/commit/a119d85) (2021-01)

## What changed vs step 180

| Rust change | C++ translation |
|---|---|
| Feature: push rule settings. Users can configure which push rules apply (e.g., notify on @mention, keywords). 3 files changed. | **Translated** — Our push rules are stubbed (step 8). This commit adds the settings API. |

## Implementation details

- Our push rules are stubbed (step 8). This commit adds the settings API.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
