# Step 384 — "improvement: better default cache capacity" (Conduit `80e5198`)

Source: [`timokoesters/conduit@80e5198`](https://github.com/timokoesters/conduit/commit/80e5198) (2022-01)

## What changed vs step 383

| Rust change | C++ translation |
|---|---|
| Improvement: better default cache capacity. Tune default cache sizes. | **Translated** — Our caches use defaults. This tunes the Rust defaults. |

## Implementation details

- Our caches use defaults. This tunes the Rust defaults.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
