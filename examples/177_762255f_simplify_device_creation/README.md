# Step 177 — "Simplify device creation logic during login" (Conduit `762255f`)

Source: [`timokoesters/conduit@762255f`](https://github.com/timokoesters/conduit/commit/762255f) (2021-01)

## What changed vs step 176

| Rust change | C++ translation |
|---|---|
| Simplify device creation logic during login. Less code, same behavior. | **Translated** — Our device creation is in `login` handler, uses `generate_device_id`. |

## Implementation details

- Our device creation is in `login` handler, uses `generate_device_id`.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
