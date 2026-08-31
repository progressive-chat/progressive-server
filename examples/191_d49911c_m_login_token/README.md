# Step 191 — "Add 'm.login.token' authentication" (Conduit `d49911c`)

Source: [`timokoesters/conduit@d49911c`](https://github.com/timokoesters/conduit/commit/d49911c) (2021-02)

## What changed vs step 190

| Rust change | C++ translation |
|---|---|
| Add 'm.login.token' authentication. Token-based login flow (like SSO). 7 files changed. | **Translated** — We have m.login.password (step 13). m.login.token is a new auth flow for SSO. |

## Implementation details

- We have m.login.password (step 13). m.login.token is a new auth flow for SSO.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
