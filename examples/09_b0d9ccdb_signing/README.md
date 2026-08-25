# Step 9 - "Signing, basis for federation" (Conduit `b0d9ccdb`, 2020-04-22)

Source: timokoesters/conduit@b0d9ccdb - the foundation of federation: the
server generates an Ed25519 keypair, signs every PDU it appends, and signs
outgoing federation requests with X-Matrix authorization.

Folded prerequisites: keypair() on Data persisted in the DB root
(generate-on-first-boot), random tokens/devices (ddcd423e).

## What changed vs step 8

- utils::generate_keypair -> crypto::ed25519_generate_seed (OpenSSL RAND_bytes),
  raw 32-byte seed persisted in the DB root "keypair".
- ruma_signatures::hash_and_sign_event replaces the "AAAA..." hashes + fake
  "signature" TODOs: hashes.sha256 = sha256(canonical(redact(event)));
  signatures[hostname]["ed25519:<pub_b64>"] = sign(canonical(event minus
  signatures/unsigned)). See src/crypto.cpp hash_and_sign_event.
- server_server::send_request builds {method,uri,origin,destination,content},
  signs it, sets Authorization: X-Matrix origin=...,key="...",sig="...",
  delivers via httplib SSLClient. Graceful failure offline.
- publicRooms merges chunks fetched from matrix.org over federation.

## Verified

    ./build/tests
    [PASS] register returns 200
    [PASS] login with correct password returns 200
    [PASS] synced event signature verifies against embedded key
    [PASS] login with incorrect password returns M_FORBIDDEN 403

Stored event carries real hashes + signatures, e.g.:

    "hashes": {"sha256": "XEVbcvQV-krBW-4WVKA12PPFn_bg0GAXuCgO3Ll2VvU"}
    "signatures": {"localhost": {"ed25519:hQYA-75AR...": "8e5795bf..."}}

An independent verifier (OpenSSL EVP_DigestVerify against the key id's
embedded public key) confirms SIGNATURE VALID over the canonical JSON.

Study note: the first verify attempt failed because of a hand-written
base64url decoder with a broken -/_ table. Signatures were fine; the decoder
was not. Cross-checked against Python cryptography.
