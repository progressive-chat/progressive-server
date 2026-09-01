# Step 583 — "Cleanly handle invalid response from trusted server instead of panicking" (Conduit `23cf39c`)

Source: [`timokoesters/conduit@23cf39c`](https://github.com/timokoesters/conduit/commit/23cf39c) (2022-10)

## What changed vs step 582

| Rust change | C++ translation |
|---|---|
| Cleanly handle invalid response from trusted server instead of panicking. Trusted key server error handling. 1 file changed. | **Translated** — Our key fetching (step 8, 214) handles errors. This prevents a panic. |

## Implementation details

- Our key fetching (step 8, 214) handles errors. This prevents a panic.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
