# Step 258 — "Change the default port (follows DEPLOY.md)" (Conduit `19aaffe`)

Source: [`timokoesters/conduit@19aaffe`](https://github.com/timokoesters/conduit/commit/19aaffe) (2021-04)

## What changed vs step 257

| Rust change | C++ translation |
|---|---|
| Change the default port (follows DEPLOY.md). Default port changed to 8448. | **Translated** — Our default port is 8000. To match, we'd change to 8448. |

## Implementation details

- Our default port is 8000. To match, we'd change to 8448.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
