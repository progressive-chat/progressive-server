# Step 233 — "improvement: better logging" (Conduit `1d00a8c`)

Source: [`timokoesters/conduit@1d00a8c`](https://github.com/timokoesters/conduit/commit/1d00a8c) (2021-03)

## What changed vs step 232

| Rust change | C++ translation |
|---|---|
| Improvement: better logging. More structured and informative logs. | **Translated** — Our logging is via std::cerr. This improves Rust logging; our C++ logging is simpler. |

## Implementation details

- Our logging is via std::cerr. This improves Rust logging; our C++ logging is simpler.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
