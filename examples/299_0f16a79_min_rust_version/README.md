# Step 299 — "Specify the minimum required Rust version in the manifest" (Conduit `0f16a79`)

Source: [`timokoesters/conduit@0f16a79`](https://github.com/timokoesters/conduit/commit/0f16a79) (2021-05)

## What changed vs step 298

| Rust change | C++ translation |
|---|---|
| Specify the minimum required Rust version in the manifest. Tooling metadata. | **No-op for us** — Rust version metadata — N/A for C++. |

## Implementation details

- Rust version metadata — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
