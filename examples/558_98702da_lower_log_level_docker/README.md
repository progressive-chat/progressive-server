# Step 558 — "Lower default log level for docker" (Conduit `98702da`)

Source: [`timokoesters/conduit@98702da`](https://github.com/timokoesters/conduit/commit/98702da) (2022-10)

## What changed vs step 557

| Rust change | C++ translation |
|---|---|
| Lower default log level for docker. Docker-specific log level default. 4 files changed. | **Translated** — Docker log level — our Docker setup could use this. |

## Implementation details

- Docker log level — our Docker setup could use this.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
