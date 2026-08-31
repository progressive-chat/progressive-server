# Step 508 — "Allow registration without username" (Conduit `84ec057`)

Source: [`timokoesters/conduit@84ec057`](https://github.com/timokoesters/conduit/commit/84ec057) (2022-06)

## What changed vs step 507

| Rust change | C++ translation |
|---|---|
| Allow registration without username. Optional username during registration. 1 file changed. | **Translated** — Our registration (step 12) requires username. This makes it optional. |

## Implementation details

- Our registration (step 12) requires username. This makes it optional.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
