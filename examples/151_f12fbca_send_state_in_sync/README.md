# Step 151 — "fix: send state in /sync, element displays wrong membership changes" (Conduit `f12fbca`)

Source: [`timokoesters/conduit@f12fbca`](https://github.com/timokoesters/conduit/commit/f12fbca) (2020-12)

## What changed vs step 150

| Rust change | C++ translation |
|---|---|
| Fix: send state in `/sync`, Element displays wrong membership changes. Sends state events along with the timeline so clients can render the room state correctly. | **Translated** — Our `/sync` (step 6) already sends state events. The bug fix is in how state events are ordered with timeline events. |

## Implementation details

- Our `/sync` (step 6) already sends state events. The bug fix is in how state events are ordered with timeline events.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
