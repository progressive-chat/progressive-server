# Step 504 — "Fix FluffyChat Compatibility" (Conduit `8a63a2c`)

Source: [`timokoesters/conduit@8a63a2c`](https://github.com/timokoesters/conduit/commit/8a63a2c) (2022-06)

## What changed vs step 503

| Rust change | C++ translation |
|---|---|
| Fix FluffyChat Compatibility. Client compatibility fix. 1 file changed. | **Translated** — Client compatibility — our server works with FluffyChat. This fixes a Rust issue. |

## Implementation details

- Client compatibility — our server works with FluffyChat. This fixes a Rust issue.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
