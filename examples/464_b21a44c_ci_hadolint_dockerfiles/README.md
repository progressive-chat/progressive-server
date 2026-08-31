# Step 464 — "feat(ci): Lint dockerfiles with hadolint" (Conduit `b21a44c`)

Source: [`timokoesters/conduit@b21a44c`](https://github.com/timokoesters/conduit/commit/b21a44c) (2022-02)

## What changed vs step 463

| Rust change | C++ translation |
|---|---|
| Feat(ci): Lint dockerfiles with hadolint. Dockerfile linting in CI. | **No-op for us** — Rust CI — N/A for C++. |

## Implementation details

- Rust CI — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
