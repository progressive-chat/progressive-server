# Step 43 — "improvement: better logs on deserialization errors" (Conduit `a567cd81d`)

Source: [`timokoesters/conduit@a567cd81d`](https://github.com/timokoesters/conduit/commit/a567cd81d) (2020-09-16)

## What changed vs step 42

| Rust change | C++ translation |
|---|---|
| `send_request` now logs `httplib::to_string(res.error())` on failure. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
