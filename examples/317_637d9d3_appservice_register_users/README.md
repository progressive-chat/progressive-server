# Step 317 — "Always allow appservices to register new users" (Conduit `637d9d3`)

Source: [`timokoesters/conduit@637d9d3`](https://github.com/timokoesters/conduit/commit/637d9d3) (2021-06)

## What changed vs step 316

| Rust change | C++ translation |
|---|---|
| Always allow appservices to register new users. Appservices can create users without admin approval. | **Translated** — Our appservice (step 96) has user registration. This ensures appservices can always register. |

## Implementation details

- Our appservice (step 96) has user registration. This ensures appservices can always register.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
