# Step 707 — "Changed 'right' to 'appropriate' to avoid ambiguity (original could be read as right-hand-side)" (Conduit `9ce1cad`)

Source: [`timokoesters/conduit@9ce1cad`](https://github.com/timokoesters/conduit/commit/9ce1cad) (2023-08)

## What changed vs step 706

| Rust change | C++ translation |
|---|---|
| Changed 'right' to 'appropriate' to avoid ambiguity. Wording change in comments/docs. | **No-op for us** — Wording change — our codebase uses its own terms. |

## Implementation details

- Wording change — our codebase uses its own terms.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
