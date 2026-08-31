# Step 282 — "feat: implement GET /presence" (Conduit `2479389`)

Source: [`timokoesters/conduit@2479389`](https://github.com/timokoesters/conduit/commit/2479389) (2021-05)

## What changed vs step 281

| Rust change | C++ translation |
|---|---|
| Feat: implement GET /presence. Presence endpoint to get user presence state. 4 files changed. NEW FEATURE. | **Translated** — We don't have presence yet (gap from 2020). This adds the GET /presence API. |

## Implementation details

- We don't have presence yet (gap from 2020). This adds the GET /presence API.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
