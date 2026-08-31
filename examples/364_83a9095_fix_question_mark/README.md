# Step 364 — "fix?" (Conduit `83a9095`)

Source: [`timokoesters/conduit@83a9095`](https://github.com/timokoesters/conduit/commit/83a9095) (2022-01)

## What changed vs step 363

| Rust change | C++ translation |
|---|---|
| fix?. Unclear fix, likely minor. | **No-op for us** — Unclear Rust fix — likely minor. |

## Implementation details

- Unclear Rust fix — likely minor.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
