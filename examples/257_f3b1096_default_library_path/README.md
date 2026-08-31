# Step 257 — "Change the default library path (follows DEPLOY.md)" (Conduit `f3b1096`)

Source: [`timokoesters/conduit@f3b1096`](https://github.com/timokoesters/conduit/commit/f3b1096) (2021-04)

## What changed vs step 256

| Rust change | C++ translation |
|---|---|
| Change the default library path (follows DEPLOY.md). Deployment path configuration. | **No-op for us** — Our binary path is fixed. This is a deployment config change. |

## Implementation details

- Our binary path is fixed. This is a deployment config change.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
