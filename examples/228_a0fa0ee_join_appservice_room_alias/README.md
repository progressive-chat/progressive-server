# Step 228 — "fix: join appservice room with alias" (Conduit `a0fa0ee`)

Source: [`timokoesters/conduit@a0fa0ee`](https://github.com/timokoesters/conduit/commit/a0fa0ee) (2021-03)

## What changed vs step 227

| Rust change | C++ translation |
|---|---|
| Fix: join appservice room with alias. Allow joining appservice-created rooms via their alias. | **Translated** — Our appservice join (step 96) handles this. This fixes a specific alias case. |

## Implementation details

- Our appservice join (step 96) handles this. This fixes a specific alias case.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
