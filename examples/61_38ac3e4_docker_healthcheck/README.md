# Step 61 — "Docker add healthcheck and mention Docker Hub image" (Conduit `38ac3e4`)

Source: [`timokoesters/conduit@38ac3e4`](https://github.com/timokoesters/conduit/commit/38ac3e4) (2020-08)

## What changed vs step 60

| Rust change | C++ translation |
|---|---|
| Adds a Docker healthcheck to the Dockerfile and mentions the Docker Hub image. | **Skipped** — pure Docker infrastructure change. |

## Implementation details

- **Skipped** — pure Docker infrastructure change.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
