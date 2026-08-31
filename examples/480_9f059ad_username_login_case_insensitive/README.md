# Step 480 — "make username login case insensitive" (Conduit `9f059ad`)

Source: [`timokoesters/conduit@9f059ad`](https://github.com/timokoesters/conduit/commit/9f059ad) (2022-03)

## What changed vs step 479

| Rust change | C++ translation |
|---|---|
| Make username login case insensitive. Login handles username case-insensitively. | **Translated** — Our login (step 13) is case-sensitive. This adds case-insensitive matching. |

## Implementation details

- Our login (step 13) is case-sensitive. This adds case-insensitive matching.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
