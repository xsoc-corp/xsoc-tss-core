# xsoc-tss-core

The promoted threshold primitive for the XSOC-QSIG signing platform: a one-time
linear threshold authorization gate over a prime field. XSOC-QSIG/TQ is the first
consumer; CGA and future modes are the reason it is promoted into a shared core
rather than kept inside one mode.

What is here is real math with no mock and no stub: prime-field helpers, Shamir
split for setup and test, the per-operation linear contribution, Lagrange
reconstruction, and an over-determined consistency check. The randomness source
is injected so the crate is DSKAG-agnostic; TQ supplies a wave_derive-seeded RNG.
The post-quantum on-chain binding is the LinearCommit trait, a contract whose
module-SIS instance and parameters are selected in Phase 1.

Build and test:

    cargo test

If the arkworks imports need alignment to your pinned line, adjust the use
statements at the top of src/lib.rs. See docs for the full design and the phased
plan.

CONTROLLED / NDA. ECCN 5D002.C1. CAGE 8ZXJ8.

## What is public and what is proprietary

| Component | Status |
|---|---|
| The TQ construction and the xsoc-tss-core threshold primitive (field, Shamir, reconstruction, consistency) | Public, Apache-2.0, in this repository |
| DSKAG, its wave engine and key-derivation, the NIE attestation internals, and the production module-SIS parameters | Proprietary trade secret. Not in this repository. Export-controlled, ECCN 5D002.C1. Available under license from XSOC. |

DSKAG and NIE appear here only as black boxes. Production capability is available under license; contact licensing@xsoccorp.com.