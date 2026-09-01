# Step 650 — "fix: restricted room error is now FORBIDDEN" (Conduit `1ea27c4`)

Source: [`timokoesters/conduit@1ea27c4`](https://github.com/timokoesters/conduit/commit/1ea27c4) (2023-06)

## What changed vs step 649

| Rust change | C++ translation |
|---|---|
| Fix: restricted room error is now FORBIDDEN. Proper error code for restricted room access. 1 file changed. | **Translated** — Our restricted rooms (step 564) return 403. This fixes the Rust version. |

## Implementation details

- Our restricted rooms (step 564) return 403. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
