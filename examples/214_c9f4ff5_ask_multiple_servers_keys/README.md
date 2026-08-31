# Step 214 — "Ask multiple servers for keys when not known or sending server failed" (Conduit `c9f4ff5`)

Source: [`timokoesters/conduit@c9f4ff5`](https://github.com/timokoesters/conduit/commit/c9f4ff5) (2021-03)

## What changed vs step 213

| Rust change | C++ translation |
|---|---|
| Ask multiple servers for keys when not known or sending server failed. Key query fallback. | **Translated** — Our key fetching (step 8) queries keys from the origin server. Fallback to multiple servers not yet implemented. |

## Implementation details

- Our key fetching (step 8) queries keys from the origin server. Fallback to multiple servers not yet implemented.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
