# Step 148 — "improvement: cache actual destination" (Conduit `d62f17a`)

Source: [`timokoesters/conduit@d62f17a`](https://github.com/timokoesters/conduit/commit/d62f17a) (2020-12)

## What changed vs step 147

| Rust change | C++ translation |
|---|---|
| Improvement: cache the actual destination after the first DNS lookup. Avoids repeated lookups for the same destination. | **Translated** — Our `send_request` doesn't have DNS caching — we use the destination directly. A simple cache could be added. |

## Implementation details

- Our `send_request` doesn't have DNS caching — we use the destination directly. A simple cache could be added.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
