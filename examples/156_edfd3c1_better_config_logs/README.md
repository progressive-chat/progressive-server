# Step 156 — "improvement: better config, better logs" (Conduit `edfd3c1`)

Source: [`timokoesters/conduit@edfd3c1`](https://github.com/timokoesters/conduit/commit/edfd3c1) (2020-12)

## What changed vs step 155

| Rust change | C++ translation |
|---|---|
| Improvement: better config validation and better logging throughout. 8 files changed. | **Translated** — Our config layer (step 99 in date tail) and logging (step 6+) cover this. |

## Implementation details

- Our config layer (step 99 in date tail) and logging (step 6+) cover this.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
