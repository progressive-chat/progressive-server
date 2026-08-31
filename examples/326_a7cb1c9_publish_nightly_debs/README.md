# Step 326 — "Publish master builds as nightly releases & also build debs" (Conduit `a7cb1c9`)

Source: [`timokoesters/conduit@a7cb1c9`](https://github.com/timokoesters/conduit/commit/a7cb1c9) (2021-07)

## What changed vs step 325

| Rust change | C++ translation |
|---|---|
| Publish master builds as nightly releases & also build debs. CI/CD for nightly releases. | **No-op for us** — Rust CI/CD — our C++ builds are different. |

## Implementation details

- Rust CI/CD — our C++ builds are different.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
