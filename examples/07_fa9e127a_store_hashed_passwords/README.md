# Step 7 — "Store hashed passwords" (Conduit `fa9e127a`, 2020-04-14, PR #7)

Source: [`timokoesters/conduit@fa9e127a`](https://github.com/timokoesters/conduit/commit/fa9e127a)
— the commit that fixed step 3's plaintext-password sin: passwords are now
hashed with **Argon2id** on register and verified against the stored hash on
login.

## What changed vs step 6

| Rust change | C++ translation |
|---|---|
| `utils::calculate_hash(password)` — `argon2::hash_encoded` with `Config { variant: Argon2id, ..Default }` (m=4096 KiB, t=2, p=1, 32-byte tag), random 32-char alphanumeric salt | `utils::calculate_hash` via **libargon2**'s `argon2id_hash_encoded` (+ `random_string`) |
| register: `if let Ok(hash) = utils::calculate_hash(...)` else `M_INVALID_PARAM` "Password did not met requirements" [sic] 400 | identical, including the typo |
| login: `argon2::verify_encoded(&hash, password).unwrap_or(false)` | `argon2id_verify(hash, pwd) == ARGON2_OK`; wrong → `M_FORBIDDEN` "" @403 (matching upstream's own test), no account → `M_FORBIDDEN` "" @403 |
| `data.rs`: `user_add(user_id, hash: &str)`; rename `password_get` → `password_hash_get` | identical renames |
| new `test.rs` integration tests | `src/test.cpp` harness that spawns the real server binary and drives it over HTTP; runs the same three scenarios |

Deviations, documented:
* The first upstream test asserts UIAA (401 + flows + session) on auth-less
  register — UIAA arrived upstream Apr 6-10 and isn't translated yet, so our
  harness expects direct success.
* This sandbox only routes loopback between separate processes, so the test
  spawns `server` as a child process instead of rocket's in-process client.

## Verified

```console
$ ./build/tests
[PASS] register returns 200
[PASS] login with correct password returns 200
[PASS] login with incorrect password returns M_FORBIDDEN 403
ALL TESTS PASSED
```

On-disk proof the plaintext era is over:

```
~/.local/share/conduit-step07/000004.log:
  $argon2id$v=19$m=4096,t=2,p=1$ZFhhUThSY0ozeENUQjN2RE1jTGFoaWNreEZN...
```

## Build & run

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server            # homeserver on :8000
$ ./build/tests             # translated src/test.rs scenarios
```
