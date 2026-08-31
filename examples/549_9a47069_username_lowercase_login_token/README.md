# Step 549 — "fix(client/login): username in lowercase for login by token" (Conduit `9a47069`)

Source: [`timokoesters/conduit@9a47069`](https://github.com/timokoesters/conduit/commit/9a47069) (2022-10)

## What changed vs step 548

| Rust change | C++ translation |
|---|---|
| Fix(client/login): username in lowercase for login by token. Case-insensitive username for token login. | **Translated** — Related to step 480 (case-insensitive login). This applies to token login. |

## Implementation details

- Related to step 480 (case-insensitive login). This applies to token login.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
