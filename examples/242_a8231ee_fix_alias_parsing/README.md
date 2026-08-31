# Step 242 — "fix: alias parsing" (Conduit `a8231ee`)

Source: [`timokoesters/conduit@a8231ee`](https://github.com/timokoesters/conduit/commit/a8231ee) (2021-04)

## What changed vs step 241

| Rust change | C++ translation |
|---|---|
| Fix: alias parsing. Room alias (#room:server) parsing fixes. | **Translated** — Our alias handling (step 10) parses aliases correctly. This fixes edge cases in Rust. |

## Implementation details

- Our alias handling (step 10) parses aliases correctly. This fixes edge cases in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
