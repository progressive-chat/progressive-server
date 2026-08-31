# Step 290 — "Add CONDUIT_CONFIG to all relevant docker files And mention that an empty string can be used to configure Conduit purely with env vars." (Conduit `5a7ccbd`)

Source: [`timokoesters/conduit@5a7ccbd`](https://github.com/timokoesters/conduit/commit/5a7ccbd) (2021-05)

## What changed vs step 289

| Rust change | C++ translation |
|---|---|
| Add CONDUIT_CONFIG to all relevant docker files. Config via env var support. 5 files changed. | **Translated** — Our config is file-based. Env var override would be new. |

## Implementation details

- Our config is file-based. Env var override would be new.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
