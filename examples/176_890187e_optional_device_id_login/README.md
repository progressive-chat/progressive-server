# Step 176 — "improvement: Handle optional device_id field during login" (Conduit `890187e`)

Source: [`timokoesters/conduit@890187e`](https://github.com/timokoesters/conduit/commit/890187e) (2021-01)

## What changed vs step 175

| Rust change | C++ translation |
|---|---|
| Improvement: Handle optional `device_id` field during login. If not provided, generate one. | **Translated** — Our `/login` (step 13 `4e6478b_login`) already generates device_id if not provided. |

## Implementation details

- Our `/login` (step 13 `4e6478b_login`) already generates device_id if not provided.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
