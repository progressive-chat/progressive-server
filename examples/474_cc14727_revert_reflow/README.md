# Step 474 — "revert reflow" (Conduit `cc14727`)

Source: [`timokoesters/conduit@cc14727`](https://github.com/timokoesters/conduit/commit/cc14727) (2022-02)

## What changed vs step 473

| Rust change | C++ translation |
|---|---|
| Revert reflow. Code formatting revert. | **No-op for us** — Rust formatting revert — our C++ uses clang-format. |

## Implementation details

- Rust formatting revert — our C++ uses clang-format.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
