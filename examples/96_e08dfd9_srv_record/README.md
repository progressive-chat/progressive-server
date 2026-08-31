# Step 96 — "improvement: look at SRV record when sending requests" (Conduit `e08dfd9`)

Source: [`timokoesters/conduit@e08dfd9`](https://github.com/timokoesters/conduit/commit/e08dfd9) (2020-09)

## What changed vs step 95

| Rust change | C++ translation |
|---|---|
| Look at DNS SRV records when sending federation requests to discover the right port. | **Translated** — Our `send_request` uses port 8448 directly. SRV record lookup is a future enhancement. |

## Implementation details

- Our `send_request` uses port 8448 directly. SRV record lookup is a future enhancement.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
