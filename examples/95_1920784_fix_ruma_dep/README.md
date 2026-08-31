# Step 95 — "Fix ruma dependency" (Conduit `1920784`)

Source: [`timokoesters/conduit@1920784`](https://github.com/timokoesters/conduit/commit/1920784) (2020-09)

## What changed vs step 94

| Rust change | C++ translation |
|---|---|
| Fix the ruma dependency version. | ****Skipped**** — Pure dependency fix. |

## Implementation details

- Pure dependency fix.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
