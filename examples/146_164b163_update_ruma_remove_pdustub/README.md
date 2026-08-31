# Step 146 — "Update ruma to latest, renamed server keys and removed PduStub" (Conduit `164b163`)

Source: [`timokoesters/conduit@164b163`](https://github.com/timokoesters/conduit/commit/164b163) (2020-12)

## What changed vs step 145

| Rust change | C++ translation |
|---|---|
| Update ruma to latest, renamed server keys and removed PduStub. 19 files changed. | **Skipped** — ruma update + Rust PduStub type removal. No code we can reuse in C++. |

## Implementation details

- ruma update + Rust PduStub type removal. No code we can reuse in C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
