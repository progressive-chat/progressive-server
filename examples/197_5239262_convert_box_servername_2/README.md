# Step 197 — "Convert uses of Box<ServerName> to a ref" (Conduit `5239262`)

Source: [`timokoesters/conduit@5239262`](https://github.com/timokoesters/conduit/commit/5239262) (2021-02)

## What changed vs step 196

| Rust change | C++ translation |
|---|---|
| Convert uses of `Box<ServerName>` to a `&ServerName` ref. Duplicate of step 171 (2ac3ffb). | **No-op for us** — Our `std::string` for server names is on the stack, no Box equivalent. |

## Implementation details

- Our `std::string` for server names is on the stack, no Box equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
