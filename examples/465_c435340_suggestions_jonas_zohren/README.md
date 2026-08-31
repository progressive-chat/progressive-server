# Step 465 — "Suggestions from Jonas Zohren" (Conduit `c435340`)

Source: [`timokoesters/conduit@c435340`](https://github.com/timokoesters/conduit/commit/c435340) (2022-02)

## What changed vs step 464

| Rust change | C++ translation |
|---|---|
| Suggestions from Jonas Zohren. Code review feedback. 4 files changed. | **Translated** — Code review fixes — applied to our equivalent code. |

## Implementation details

- Code review fixes — applied to our equivalent code.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
