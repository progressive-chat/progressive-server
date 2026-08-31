# Step 171 — "Convert uses of Box<ServerName> to a ref" (Conduit `2ac3ffb`)

Source: [`timokoesters/conduit@2ac3ffb`](https://github.com/timokoesters/conduit/commit/2ac3ffb) (2021-01)

## What changed vs step 170

| Rust change | C++ translation |
|---|---|
| Convert uses of `Box<ServerName>` to a `&ServerName` ref. Performance optimization (no heap allocation for server names). | **No-op for us** — Our `std::string` for server names is on the stack, no Box equivalent. |

## Implementation details

- Our `std::string` for server names is on the stack, no Box equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
