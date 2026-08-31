# Step 335 — "apply lint suggestions and version bump" (Conduit `e1b89c1`)

Source: [`timokoesters/conduit@e1b89c1`](https://github.com/timokoesters/conduit/commit/e1b89c1) (2021-07)

## What changed vs step 334

| Rust change | C++ translation |
|---|---|
| Apply lint suggestions and version bump. Code quality improvements from linter. | **Translated** — Code quality — our codebase uses similar patterns. |

## Implementation details

- Code quality — our codebase uses similar patterns.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
