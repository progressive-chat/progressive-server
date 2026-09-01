# Step 698 — "Only print raw malformed JSON body in debug level" (Conduit `1f867a2`)

Source: [`timokoesters/conduit@1f867a2`](https://github.com/timokoesters/conduit/commit/1f867a2) (2023-07)

## What changed vs step 697

| Rust change | C++ translation |
|---|---|
| Only print raw malformed JSON body in debug level. Don't log malformed JSON at info level. | **Translated** — Our JSON parsing logs errors. This moves malformed JSON to debug level. |

## Implementation details

- Our JSON parsing logs errors. This moves malformed JSON to debug level.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
