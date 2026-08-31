# Step 487 — "chore(docker): Bump alpine (base image) version" (Conduit `6127745`)

Source: [`timokoesters/conduit@6127745`](https://github.com/timokoesters/conduit/commit/6127745) (2022-03)

## What changed vs step 486

| Rust change | C++ translation |
|---|---|
| Chore(docker): Bump alpine (base image) version. Docker base image update. | **No-op for us** — Docker base image — our C++ uses different base. |

## Implementation details

- Docker base image — our C++ uses different base.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
