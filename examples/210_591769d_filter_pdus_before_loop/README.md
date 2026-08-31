# Step 210 — "Fiter PDU's before main incoming PDU loop" (Conduit `591769d`)

Source: [`timokoesters/conduit@591769d`](https://github.com/timokoesters/conduit/commit/591769d) (2021-02)

## What changed vs step 209

| Rust change | C++ translation |
|---|---|
| Filter PDUs before main incoming PDU loop. Skip events we already know about early. | **Translated** — Our incoming event handler (step 83) checks if event exists before processing. |

## Implementation details

- Our incoming event handler (step 83) checks if event exists before processing.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
