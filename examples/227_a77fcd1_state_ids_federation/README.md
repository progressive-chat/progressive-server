# Step 227 — "feat: implement /state_ids and fix federation stuff" (Conduit `a77fcd1`)

Source: [`timokoesters/conduit@a77fcd1`](https://github.com/timokoesters/conduit/commit/a77fcd1) (2021-03)

## What changed vs step 226

| Rust change | C++ translation |
|---|---|
| Feat: implement `/state_ids` and fix federation stuff. The `/state_ids` endpoint returns event IDs for current room state. 4 files changed. | **Translated** — We don't have `/state_ids` yet. This adds the API for getting state event IDs. |

## Implementation details

- We don't have `/state_ids` yet. This adds the API for getting state event IDs.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
