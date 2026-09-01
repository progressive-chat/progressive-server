# Step 708 — "Correct option error adduser in DEPLOY.md" (Conduit `3a6eee7`)

Source: [`timokoesters/conduit@3a6eee7`](https://github.com/timokoesters/conduit/commit/3a6eee7) (2023-08)

## What changed vs step 707

| Rust change | C++ translation |
|---|---|
| Correct option error adduser in DEPLOY.md. Documentation fix. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
