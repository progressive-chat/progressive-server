# Step 409 — "fix: make sure libstdc++ is linked statically when cross-compiling" (Conduit `3e9abfe`)

Source: [`timokoesters/conduit@3e9abfe`](https://github.com/timokoesters/conduit/commit/3e9abfe) (2022-01)

## What changed vs step 408

| Rust change | C++ translation |
|---|---|
| Fix: make sure libstdc++ is linked statically when cross-compiling. Cross-compile fix. | **No-op for us** — Rust cross-compile — our C++ cross-compiles differently. |

## Implementation details

- Rust cross-compile — our C++ cross-compiles differently.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
