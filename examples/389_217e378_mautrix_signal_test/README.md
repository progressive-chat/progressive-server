# Step 389 — "Add mautrix-signal to tested appservices" (Conduit `217e378`)

Source: [`timokoesters/conduit@217e378`](https://github.com/timokoesters/conduit/commit/217e378) (2022-01)

## What changed vs step 388

| Rust change | C++ translation |
|---|---|
| Add mautrix-signal to tested appservices. CI test matrix addition. | **No-op for us** — CI test configuration — N/A for C++. |

## Implementation details

- CI test configuration — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
