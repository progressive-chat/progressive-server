# Step 240 — "Use BTreeMap::into_values" (Conduit `6bb1081`)

Source: [`timokoesters/conduit@6bb1081`](https://github.com/timokoesters/conduit/commit/6bb1081) (2022-01-20)

## What changed vs step 239

| Rust change | C++ translation |
|---|---|
| **BTreeMap::into_values** | **Translated** — BTreeMap::into_values |

## Implementation details

1. **BTreeMap::into_values** — Use BTreeMap::into_values (stable under new MSRV)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
