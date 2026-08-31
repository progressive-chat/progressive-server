# Step 209 — "Use eventId when saving outliers" (Conduit `64374b4`)

Source: [`timokoesters/conduit@64374b4`](https://github.com/timokoesters/conduit/commit/64374b4) (2021-02)

## What changed vs step 208

| Rust change | C++ translation |
|---|---|
| Use eventId when saving outliers. Outliers are now keyed by event ID instead of some other key. | **Translated** — Our outlier storage uses event ID as the key. |

## Implementation details

- Our outlier storage uses event ID as the key.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
