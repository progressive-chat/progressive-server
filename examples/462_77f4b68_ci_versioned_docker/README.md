# Step 462 — "fix(ci): Also create versioned docker image" (Conduit `77f4b68`)

Source: [`timokoesters/conduit@77f4b68`](https://github.com/timokoesters/conduit/commit/77f4b68) (2022-02)

## What changed vs step 461

| Rust change | C++ translation |
|---|---|
| Fix(ci): Also create versioned docker image. CI Docker image tagging. | **No-op for us** — Rust CI Docker — our C++ uses different CI. |

## Implementation details

- Rust CI Docker — our C++ uses different CI.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
