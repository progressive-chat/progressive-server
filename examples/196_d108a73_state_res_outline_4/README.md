# Step 196 — "State resolution outline for /send" (Conduit `d108a73`)

Source: [`timokoesters/conduit@d108a73`](https://github.com/timokoesters/conduit/commit/d108a73) (2021-02)

## What changed vs step 195

| Rust change | C++ translation |
|---|---|
| State resolution outline for `/send`. Another iteration. | **Translated** — Our step 83 implements the final state-res. |

## Implementation details

- Our step 83 implements the final state-res.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
