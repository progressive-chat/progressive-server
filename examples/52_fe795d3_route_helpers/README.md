# Step 52 — "Replace route calling routes with helpers" (Conduit `fe795d38`)

Source: [`timokoesters/conduit@fe795d38`](https://github.com/timokoesters/conduit/commit/fe795d38) (2020-08)

## What changed vs step 51

| Rust change | C++ translation |
|---|---|
| Replaces the `State<'_, Database>` wrapper with `&Database` in all helper functions. Fixes the 'index out of bounds' panic from ruma when routes called routes. | **No-op for us** — our C++ code already covers this functionality (see earlier steps). |

## Implementation details

- **No-op for us** — our C++ code already covers this functionality (see earlier steps).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
