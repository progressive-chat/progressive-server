# Step 582 — "Cargo Clippy" (Conduit `00996dd`)

Source: [`timokoesters/conduit@00996dd`](https://github.com/timokoesters/conduit/commit/00996dd) (2022-10)

## What changed vs step 581

| Rust change | C++ translation |
|---|---|
| Cargo Clippy. Lint fixes. | **No-op for us** — Rust linting — our C++ uses clang-tidy. |

## Implementation details

- Rust linting — our C++ uses clang-tidy.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
