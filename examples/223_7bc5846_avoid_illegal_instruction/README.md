# Step 223 — "fix: avoid illegal instruction crash" (Conduit `7bc5846`)

Source: [`timokoesters/conduit@7bc5846`](https://github.com/timokoesters/conduit/commit/7bc5846) (2021-03)

## What changed vs step 222

| Rust change | C++ translation |
|---|---|
| Fix: avoid illegal instruction crash. Some CPU instructions caused crashes on older CPUs. | **No-op for us** — Rust compiler flags issue — our C++ uses standard flags, no illegal instructions. |

## Implementation details

- Rust compiler flags issue — our C++ uses standard flags, no illegal instructions.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
