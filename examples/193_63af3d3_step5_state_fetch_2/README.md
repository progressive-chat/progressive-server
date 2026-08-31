# Step 193 — "Step 5 in /send just fetches state from incoming server" (Conduit `63af3d3`)

Source: [`timokoesters/conduit@63af3d3`](https://github.com/timokoesters/conduit/commit/63af3d3) (2021-02)

## What changed vs step 192

| Rust change | C++ translation |
|---|---|
| Step 5 in `/send` just fetches state from incoming server. Continuation of state-res work. | **Translated** — See step 192 — same work continued. |

## Implementation details

- See step 192 — same work continued.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
