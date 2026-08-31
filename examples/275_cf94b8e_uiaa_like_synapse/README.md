# Step 275 — "improvement: uiaa works like in synapse" (Conduit `cf94b8e`)

Source: [`timokoesters/conduit@cf94b8e`](https://github.com/timokoesters/conduit/commit/cf94b8e) (2021-05)

## What changed vs step 274

| Rust change | C++ translation |
|---|---|
| Improvement: UIAA works like in Synapse. User-Interactive Authentication API now matches Synapse behavior. 10 files changed. MAJOR auth improvement. | **Translated** — Our UIAA (step 17 `f34c698_uiaa`) is basic. This brings it to Synapse parity. |

## Implementation details

- Our UIAA (step 17 `f34c698_uiaa`) is basic. This brings it to Synapse parity.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
