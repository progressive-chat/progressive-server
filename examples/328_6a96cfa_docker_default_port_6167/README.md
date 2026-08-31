# Step 328 — "Change default port in docker to the new  conduit default port 6167 and fix the docker healthcheck" (Conduit `6a96cfa`)

Source: [`timokoesters/conduit@6a96cfa`](https://github.com/timokoesters/conduit/commit/6a96cfa) (2021-07)

## What changed vs step 327

| Rust change | C++ translation |
|---|---|
| Change default port in docker to the new conduit default port 6167 and fix docker healthcheck. Docker port change. | **Translated** — Our default port is 8000. Conduit changed to 6167. Docker config only. |

## Implementation details

- Our default port is 8000. Conduit changed to 6167. Docker config only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
