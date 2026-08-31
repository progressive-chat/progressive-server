# Step 507 — "chore(docker): Bump base image to alpine 3.16.0" (Conduit `e03a2b8`)

Source: [`timokoesters/conduit@e03a2b8`](https://github.com/timokoesters/conduit/commit/e03a2b8) (2022-06)

## What changed vs step 506

| Rust change | C++ translation |
|---|---|
| Chore(docker): Bump base image to alpine 3.16.0. Docker base image update. | **No-op for us** — Docker base image — our C++ uses different base. |

## Implementation details

- Docker base image — our C++ uses different base.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
