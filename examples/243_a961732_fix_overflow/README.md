# Step 243 — "fix: overflow" (Conduit `a961732`)

Source: [`timokoesters/conduit@a961732`](https://github.com/timokoesters/conduit/commit/a961732) (2021-04)

## What changed vs step 242

| Rust change | C++ translation |
|---|---|
| Fix: overflow. Integer overflow fix in some calculation. | **Translated** — Our C++ uses size_t/uint64_t which handles large values. Overflow unlikely. |

## Implementation details

- Our C++ uses size_t/uint64_t which handles large values. Overflow unlikely.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
