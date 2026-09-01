# Step 732 — "create_hash_and_sign_event: Use actual version of RoomCreate events, instead of the default" (Conduit `fac9950`)

Source: [`timokoesters/conduit@fac9950`](https://github.com/timokoesters/conduit/commit/fac9950) (2023-12)

## What changed vs step 731

| Rust change | C++ translation |
|---|---|
| create_hash_and_sign_event: Use actual version of RoomCreate events, instead of the default. Room create event versioning. 1 file changed. | **Translated** — Our room create (step 10) uses correct version. This fixes Rust version. |

## Implementation details

- Our room create (step 10) uses correct version. This fixes Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
