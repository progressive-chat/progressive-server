# Step 91 — "Add Complement dockerfile and move sytest dir" (Conduit `3e03787`)

Source: [`timokoesters/conduit@3e03787`](https://github.com/timokoesters/conduit/commit/3e03787) (2020-09)

## What changed vs step 90

| Rust change | C++ translation |
|---|---|
| Adds the Complement test Dockerfile and moves the sytest directory. CI/test infrastructure. | Pure CI/test infrastructure change. |

## Implementation details

- Pure CI/test infrastructure change.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
