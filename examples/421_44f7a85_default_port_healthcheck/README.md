# Step 421 — "fix: Use default port for healthcheck as fallback" (Conduit `44f7a85`)

Source: [`timokoesters/conduit@44f7a85`](https://github.com/timokoesters/conduit/commit/44f7a85) (2022-01)

## What changed vs step 420

| Rust change | C++ translation |
|---|---|
| Fix: Use default port for healthcheck as fallback. Healthcheck port configuration. 1 file changed. | **Translated** — Our healthcheck uses the server port. This adds a fallback default. |

## Implementation details

- Our healthcheck uses the server port. This adds a fallback default.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
