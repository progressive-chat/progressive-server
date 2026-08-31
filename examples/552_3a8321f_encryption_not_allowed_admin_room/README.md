# Step 552 — "feat(db/rooms): encryption is not allowed in the admins room" (Conduit `3a8321f`)

Source: [`timokoesters/conduit@3a8321f`](https://github.com/timokoesters/conduit/commit/3a8321f) (2022-10)

## What changed vs step 551

| Rust change | C++ translation |
|---|---|
| Feat(db/rooms): encryption is not allowed in the admins room. Admin room encryption restriction. 1 file changed. | **Translated** — Our admin room (step 60) doesn't have encryption. This enforces the restriction in Rust. |

## Implementation details

- Our admin room (step 60) doesn't have encryption. This enforces the restriction in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
