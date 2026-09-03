# Step 259: bfbefb0c - Display actual error message from TokioAsyncResolver

**Conduit commit:** `bfbefb0cd2e90549c41247b407d40ad9e1b128b8`
**Date:** 2022-02-07
**Author:** Andrej Kacian

## Summary

This commit adds error logging when the DNS resolver (TokioAsyncResolver) fails to initialize with the system configuration. The change captures the actual error message and logs it before returning the error.

## Changes in Conduit

```rust
// Before:
dns_resolver: TokioAsyncResolver::tokio_from_system_conf().map_err(|_| {
    Error::bad_config("Failed to set up trust dns resolver with system config.")
})?,

// After:
dns_resolver: TokioAsyncResolver::tokio_from_system_conf().map_err(|e| {
    error!(
        "Failed to set up trust dns resolver with system config: {}",
        e
    );
    Error::bad_config("Failed to set up trust dns resolver with system config.")
})?,
```

## C++ Translation

This change does not apply to our C++ translation. We use cpp-httplib for HTTP communication, which handles DNS resolution internally through the system's standard resolver. There is no separate DNS resolver component to configure or log errors from.

**Status:** No code changes required. This step is a placeholder to maintain chronological correspondence with Conduit commits.
