# xsoc-tss-core

The promoted threshold primitive for the XSOC-QSIG signing platform: a one-time
linear threshold authorization gate over a prime field. XSOC-QSIG/TQ is the first
consumer; CGA and future modes are the reason it is promoted into a shared core
rather than kept inside one mode.

What is here is real math with no mock and no stub: prime-field helpers, Shamir
split for setup and test, the per-operation linear contribution, Lagrange
reconstruction, and an over-determined consistency check. The randomness source
is injected so the crate is DSKAG-agnostic; TQ supplies a wave_derive-seeded RNG.
The post-quantum on-chain binding is the LinearCommit trait, with a generic,
parameter-injected reference instance in src/module_sis.rs: the BDLOP module-SIS
commitment, additively homomorphic and binding on module-SIS, where the field,
the dimensions, the norm bound, and the CRS are all constructor arguments. The
production instance, the ratified parameters and the DSKAG-seeded CRS, is selected
in Phase 1 and lives outside this crate.

Build and test:

    cargo test

If the arkworks imports need alignment to your pinned line, adjust the use
statements at the top of src/lib.rs. See docs for the full design and the phased
plan.

## What is public and what is proprietary

| Component | Status |
|---|---|
| The TQ construction, the xsoc-tss-core threshold primitive (field, Shamir, reconstruction, consistency), and the LinearCommit module-SIS reference (the commitment algebra) | Public, Apache-2.0, in this repository |
| DSKAG, its wave engine and key-derivation, the NIE attestation internals, and the production module-SIS parameters and CRS | Proprietary trade secret. Not in this repository. Export-controlled, ECCN 5D002.C1. Available under license from XSOC. |

The published source is Apache-2.0 prior art. ECCN 5D002.C1 applies to the
compiled binaries and the proprietary layer below, not to this source. DSKAG and
NIE appear here only as black boxes. Production capability is available under
license; contact licensing@xsoccorp.com.
