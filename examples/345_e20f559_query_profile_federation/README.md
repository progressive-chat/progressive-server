# Step 345 — "feat: call /query/profile over federation when local user asks" (Conduit `e20f559`)

Source: [`timokoesters/conduit@e20f559`](https://github.com/timokoesters/conduit/commit/e20f559) (2021-07)

## What changed vs step 344

| Rust change | C++ translation |
|---|---|
| Feat: call /query/profile over federation when local user asks. Fetch remote user profiles. 1 file changed. | **Translated** — Our profile (step 10) is local. This adds federation profile queries. |

## Implementation details

- Our profile (step 10) is local. This adds federation profile queries.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
