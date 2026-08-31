# Step 404 — "Use BTreeMap::into_values" (Conduit `6bb1081`)

Source: [`timokoesters/conduit@6bb1081`](https://github.com/timokoesters/conduit/commit/6bb1081) (2022-01)

## What changed vs step 403

| Rust change | C++ translation |
|---|---|
| Use BTreeMap::into_values. Rust standard library optimization. | **No-op for us** — Rust BTreeMap method — our C++ uses different containers. |

## Implementation details

- Rust BTreeMap method — our C++ uses different containers.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
