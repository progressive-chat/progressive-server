# Step 427 — "feat: cache capacity modifier" (Conduit `caf9834`)

Source: [`timokoesters/conduit@caf9834`](https://github.com/timokoesters/conduit/commit/caf9834) (2022-02)

## What changed vs step 426

| Rust change | C++ translation |
|---|---|
| Feat: cache capacity modifier. Config option to modify cache capacity at runtime. 1 file changed. | **Translated** — Our cache capacity (step 382/384) is static. This adds runtime modifier. |

## Implementation details

- Our cache capacity (step 382/384) is static. This adds runtime modifier.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
