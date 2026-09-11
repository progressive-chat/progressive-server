# Step 154 — "improvement: don't send pdus to appservices if it isn't interested" (Conduit `2cf6fd5`)

Source: [`timokoesters/conduit@2cf6fd5`](https://github.com/timokoesters/conduit/commit/2cf6fd5) (2020-12-23)

Upstream filters PDU delivery to appservices by namespace interest (user /
alias / room regexes, bridge-user membership).

## What changed vs step 153

**Nothing in `src/` — this directory was a byte-identical copy.** This port
stores appservice namespaces at registration but never forwards PDUs to
appservices, so there is no delivery to filter.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit154 && ./build/tests
```
