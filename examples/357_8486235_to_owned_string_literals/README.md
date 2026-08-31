# Step 357 — "Replace to_string calls on string literals with to_owned" (Conduit `8486235`)

Source: [`timokoesters/conduit@8486235`](https://github.com/timokoesters/conduit/commit/8486235) (2022-01)

## What changed vs step 356

| Rust change | C++ translation |
|---|---|
| Replace to_string calls on string literals with to_owned. Rust string optimization. | **No-op for us** — Rust string handling — our C++ uses std::string directly. |

## Implementation details

- Rust string handling — our C++ uses std::string directly.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
