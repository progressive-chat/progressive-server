# Step 459 — "Change this to handler" (Conduit `aee6bf7`)

Source: [`timokoesters/conduit@aee6bf7`](https://github.com/timokoesters/conduit/commit/aee6bf7) (2022-02)

## What changed vs step 458

| Rust change | C++ translation |
|---|---|
| Change this to handler. Route handler refactor. | **Translated** — Route handler change — our httplib uses different handler pattern. |

## Implementation details

- Route handler change — our httplib uses different handler pattern.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
