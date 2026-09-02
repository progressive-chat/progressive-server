# Step 221 — "Use Box to store UserID and DeviceID" (Conduit `c4a4384`)

Source: [`timokoesters/conduit@c4a4384`](https://github.com/timokoesters/conduit/commit/c4a4384) (2021-12-22)

## What changed vs step 220

| Rust change | C++ translation |
|---|---|
| **Box UserID and DeviceID** | **Translated** — Box UserID/DeviceID |

## Implementation details

1. **Box UserID/DeviceID** — Use Box to store UserID and DeviceID (Userid and DeviceID are of unknown size, use Box to store them in BTreeMap)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
