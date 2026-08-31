# Step 149 — "feat: implement appservices" (Conduit `6e5b35e`)

Source: [`timokoesters/conduit@6e5b35e`](https://github.com/timokoesters/conduit/commit/6e5b35e) (2020-12)

## What changed vs step 148

| Rust change | C++ translation |
|---|---|
| MAJOR: feat: implement appservices. The appservice (bridge) protocol — appservices register to receive events, can create users/rooms on behalf of users. 26 files changed. | **Translated** — Our step 96 (`98e2bed_appservice_auth_fix`) + step 62 (`dc5abd6_appservice_pinging`) + the appservice dispatch hook in step 31/45/96 cover the appservice protocol implementation. |

## Implementation details

- Our step 96 (`98e2bed_appservice_auth_fix`) + step 62 (`dc5abd6_appservice_pinging`) + the appservice dispatch hook in step 31/45/96 cover the appservice protocol implementation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
