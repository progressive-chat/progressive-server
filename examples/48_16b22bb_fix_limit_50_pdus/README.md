# Step 48 — "fix: don't allow more than 50 PDUs in a transaction" (Conduit `16b22bb`)

Source: [`timokoesters/conduit@16b22bb`](https://github.com/timokoesters/conduit/commit/16b22bb) (2020-11-03)

## What changed vs step 47

| Rust change | C++ translation |
|---|---|
| **Added filter to skip empty PDUs** | **Translated** — Added filter to skip empty PDUs |
| **Added limit of 50 PDUs per transaction** | **Translated** — Added `.take(50)` to limit PDUs per transaction |
| **Filter empty PDUs when collecting new PDUs** | **Translated** — Added `.filter(|pdu| !pdu.is_empty())` |

## Implementation details

1. **Added `.filter(|pdu| !pdu.is_empty())`** to skip empty PDUs in the sending logic
2. **Added `.take(50)`** to limit to 50 PDUs per transaction
3. **Added `.filter(|pdu| !pdu.is_empty())`** when collecting new PDUs for retry

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
