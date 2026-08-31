# Step 491 — "fix: allow trailing slashes for /state/<type>/ again" (Conduit `a5465df`)

Source: [`timokoesters/conduit@a5465df`](https://github.com/timokoesters/conduit/commit/a5465df) (2022-04)

## What changed vs step 490

| Rust change | C++ translation |
|---|---|
| Fix: allow trailing slashes for /state/<type>/ again. Route path tolerance. 1 file changed. | **Translated** — Our routes (httplib) handle trailing slashes. This re-adds tolerance in Rust. |

## Implementation details

- Our routes (httplib) handle trailing slashes. This re-adds tolerance in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
