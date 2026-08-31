# Step 65 — "Fix review issues, move state-res to spec-comp branch" (Conduit `f46c2d1`)

Source: [`timokoesters/conduit@f46c2d1`](https://github.com/timokoesters/conduit/commit/f46c2d1) (2020-08)

## What changed vs step 64

| Rust change | C++ translation |
|---|---|
| Review feedback cleanup for the state-res branch. | **No-op for us** — folded into our state_res.cpp from step 83. |

## Implementation details

- **No-op for us** — folded into our state_res.cpp from step 83.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
