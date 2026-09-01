# Step 754 — "don't bother with mold" (Conduit `249fc77`)

Source: [`timokoesters/conduit@249fc77`](https://github.com/timokoesters/conduit/commit/249fc77) (2024-01)

## What changed vs step 753

| Rust change | C++ translation |
|---|---|
| Don't bother with mold. Linker (mold) not needed. 1 file changed. | **Skipped** — Rust linker only. |

## Implementation details

- Rust linker only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
