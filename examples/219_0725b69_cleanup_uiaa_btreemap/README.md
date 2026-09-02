# Step 219 — "Clean up userdevicesessionid_uiaarequest BTreeMap" (Conduit `0725b69`)

Source: [`timokoesters/conduit@0725b69`](https://github.com/timokoesters/conduit/commit/0725b69) (2021-12-18)

## What changed vs step 218

| Rust change | C++ translation |
|---|---|
| **Cleanup UIAA BTreeMap** | **Translated** — UIAA BTreeMap cleanup |

## Implementation details

1. **UIAA BTreeMap cleanup** — Clean up userdevicesessionid_uiaarequest BTreeMap (no need to encode/decode as we are not saving to disk)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
