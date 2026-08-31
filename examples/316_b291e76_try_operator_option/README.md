# Step 316 — "Use try operator for Option more" (Conduit `b291e76`)

Source: [`timokoesters/conduit@b291e76`](https://github.com/timokoesters/conduit/commit/b291e76) (2021-06)

## What changed vs step 315

| Rust change | C++ translation |
|---|---|
| Use try operator (?) for Option more. Rust idiomatic error handling with ? operator on Option. | **No-op for us** — Rust ? operator on Option — our C++ uses explicit checks. |

## Implementation details

- Rust ? operator on Option — our C++ uses explicit checks.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
