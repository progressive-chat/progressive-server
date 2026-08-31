# Step 254 — "No longer use/support a local environment file" (Conduit `ab58609`)

Source: [`timokoesters/conduit@ab58609`](https://github.com/timokoesters/conduit/commit/ab58609) (2021-04)

## What changed vs step 253

| Rust change | C++ translation |
|---|---|
| No longer use/support a local environment file. Config is now file-based (conduit.toml) only. | **Translated** — Our config is file-based (step 99 in tail). This removes env file support. |

## Implementation details

- Our config is file-based (step 99 in tail). This removes env file support.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
