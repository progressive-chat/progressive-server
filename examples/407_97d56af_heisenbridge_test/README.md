# Step 407 — "Add heisenbridge to tested appservices" (Conduit `97d56af`)

Source: [`timokoesters/conduit@97d56af`](https://github.com/timokoesters/conduit/commit/97d56af) (2022-01)

## What changed vs step 406

| Rust change | C++ translation |
|---|---|
| Add heisenbridge to tested appservices. CI test matrix addition. | **No-op for us** — CI test configuration — N/A for C++. |

## Implementation details

- CI test configuration — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
