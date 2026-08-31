# Step 466 — "Set all env vars in docker README" (Conduit `0be8500`)

Source: [`timokoesters/conduit@0be8500`](https://github.com/timokoesters/conduit/commit/0be8500) (2022-02)

## What changed vs step 465

| Rust change | C++ translation |
|---|---|
| Set all env vars in docker README. Documentation update. 2 files changed. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
