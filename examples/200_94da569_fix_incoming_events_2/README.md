# Step 200 — "Fixing the incoming events algorithm (review with time)" (Conduit `94da569`)

Source: [`timokoesters/conduit@94da569`](https://github.com/timokoesters/conduit/commit/94da569) (2021-02)

## What changed vs step 199

| Rust change | C++ translation |
|---|---|
| Fixing the incoming events algorithm (review with time). Duplicate of step 174 (b1ae2bb). | **Translated** — Our state-res (step 83) handles incoming events correctly. |

## Implementation details

- Our state-res (step 83) handles incoming events correctly.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
