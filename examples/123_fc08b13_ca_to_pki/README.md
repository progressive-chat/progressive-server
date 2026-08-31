# Step 123 — "Change CA to PKI per naming in Complement" (Conduit `fc08b13`)

Source: [`timokoesters/conduit@fc08b13`](https://github.com/timokoesters/conduit/commit/fc08b13) (2020-11)

## What changed vs step 122

| Rust change | C++ translation |
|---|---|
| Change CA to PKI per naming in Complement (Certificate Authority → Public Key Infrastructure). | **No-op for us** — We don't have a CA/PKI setup — our federation uses Ed25519 key pairs directly. |

## Implementation details

- We don't have a CA/PKI setup — our federation uses Ed25519 key pairs directly.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
