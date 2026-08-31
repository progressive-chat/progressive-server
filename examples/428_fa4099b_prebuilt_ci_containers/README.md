# Step 428 — "Use prebuilt CI-containers from https://gitlab.com/jfowl/conduit-containers" (Conduit `fa4099b`)

Source: [`timokoesters/conduit@fa4099b`](https://github.com/timokoesters/conduit/commit/fa4099b) (2022-02)

## What changed vs step 427

| Rust change | C++ translation |
|---|---|
| Use prebuilt CI-containers from https://gitlab.com/jfowl/conduit-containers. CI infrastructure change. 4 files changed. | **No-op for us** — Rust CI containers — our C++ uses different CI. |

## Implementation details

- Rust CI containers — our C++ uses different CI.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
