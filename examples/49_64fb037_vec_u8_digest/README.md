# Step 49 — "Use Vec<u8> instead of string for digest bytes and add roomid_statehash" (Conduit `64fb0374`)

Source: [`timokoesters/conduit@64fb0374`](https://github.com/timokoesters/conduit/commit/64fb0374) (2020-08)

## What changed vs step 48

| Rust change | C++ translation |
|---|---|
| Changes `StateHashId` type alias from `String` to `Vec<u8>` to avoid UTF-8 roundtrip on hash bytes. | **No-op for us** — our C++ code already covers this functionality (see earlier steps). |

## Implementation details

- **No-op for us** — our C++ code already covers this functionality (see earlier steps).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
