# Step 235 — "No need to log out and back in fix" (Conduit `246e473`)

Source: [`timokoesters/conduit@246e473`](https://github.com/timokoesters/conduit/commit/246e473) (2021-04)

## What changed vs step 234

| Rust change | C++ translation |
|---|---|
| Fix: No need to log out and back in after some changes. Session persistence improvement. | **Translated** — Our session handling doesn't require logout. This is a Rust session store fix. |

## Implementation details

- Our session handling doesn't require logout. This is a Rust session store fix.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
