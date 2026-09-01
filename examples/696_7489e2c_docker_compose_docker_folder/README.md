# Step 696 — "moved docker-compose.yml into the docker folder" (Conduit `7489e2c`)

Source: [`timokoesters/conduit@7489e2c`](https://github.com/timokoesters/conduit/commit/7489e2c) (2023-07)

## What changed vs step 695

| Rust change | C++ translation |
|---|---|
| Moved docker-compose.yml into the docker folder. Docker file reorganization. | **Skipped** — Docker file structure only. |

## Implementation details

- Docker file structure only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
