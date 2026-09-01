# Step 611 — "Maybe fix room joins" (Conduit `809c9b4`)

Source: [`timokoesters/conduit@809c9b4`](https://github.com/timokoesters/conduit/commit/809c9b4) (2023-01)

## What changed vs step 610

| Rust change | C++ translation |
|---|---|
| Maybe fix room joins. Room join fix attempt. 1 file changed. | **Translated** — Our join (step 25, 93) works. This attempts a fix in Rust. |

## Implementation details

- Our join (step 25, 93) works. This attempts a fix in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
