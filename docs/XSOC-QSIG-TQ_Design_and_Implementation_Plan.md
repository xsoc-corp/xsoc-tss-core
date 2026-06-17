# XSOC-QSIG/TQ: Threshold Quorum Authorization

Design and implementation plan. Public release. XSOC Corp. Author: Richard Blech,
ORCID 0009-0003-4540-2134. Companion to the XSOC-QSIG specification,
https://doi.org/10.5281/zenodo.19639166.

## What is public and what is proprietary

This document publishes the XSOC-QSIG/TQ construction, protocol, and security
model. It does not disclose the proprietary components the production system
depends on.

| Component | Status |
| --- | --- |
| The TQ construction: threshold gate, linear sharing, protocol, security argument | Public, this document and the xsoc-tss-core reference |
| The xsoc-tss-core threshold primitive: field, Shamir, reconstruction, consistency | Public, Apache-2.0 |
| DSKAG, its wave engine and key-derivation construction, the NIE attestation internals, and the production module-SIS parameters | Proprietary trade secret. Not disclosed here. Export-controlled, ECCN 5D002.C1. Available under license from XSOC. |

DSKAG, NIE, and the wave engine appear here only as black boxes. The construction
is designed so no proprietary internal is required to understand, evaluate, or
reproduce the threshold layer. Production capability is available under license;
contact licensing@xsoccorp.com.

Document text: CC-BY-4.0. Reference code: Apache-2.0. Neither license extends to
the proprietary components above.

## Terminology

The threshold layer is information-theoretic, as proven in the security argument.
The system as a whole is computationally secure under stated post-quantum
assumptions, not information-theoretic or unconditional. Where this document says
information-theoretic it refers only to the threshold-secrecy and limited-use
results.

## 0. Purpose and positioning

XSOC-QSIG/TQ is a fourth sibling under QSIG main, alongside XSOC-QSIG/3P and
XSOC-QSIG/CGA, built on the same DSKAG and NIE root. Where 3P is a transfer
mode (one party hands a verifiable object down a chain) and CGA is an agent and
lineage layer, TQ is the quorum mode: t of n custody members independently
approve the same operation, and the operation is authorized only when a quorum
agrees.

Unlike 3P, TQ is not a pure composition of primitives QSIG main already holds. It
introduces a new primitive, a one-time linear threshold authorization gate. Per
the decision to serve more than one consumer, that primitive is promoted into a
shared core crate, `xsoc-tss-core`, which TQ is the first consumer of and which
CGA and future modes can draw on. TQ mode itself lives in `xsoc-sig-tq`.

The longer arc is a single signing platform: DSKAG and NIE underneath, QSIG main
and its modes (3P, CGA, TQ, and successors) above, each capturing a different
authorization shape over the same root, so that a plethora of use cases (custody
quorums, transferable receipts, agent authorization, policy gates) are served by
one fabric rather than separate products.

## 1. Threat model and goals

Parties: a custody set of n members, threshold t, a reconstructor or coordinator
(untrusted for secrecy), and an on-chain or rail-level gate that enforces
validity. Adversary may control up to t-1 members, observe all wire traffic, and
attempt replay, share substitution, and below-threshold forgery. The adversary
is quantum.

Goals:

1. Threshold secrecy. Any t-1 members learn nothing about the authorization
   secret. Information-theoretic, from Shamir.
2. Quorum unforgeability. No coalition of fewer than t members can produce a
   verifying authorization for an operation they did not jointly approve.
3. Post-quantum throughout. No primitive in the verification path depends on a
   problem Shor breaks.
4. Member attribution and revocation. Each contribution is bound to a member
   identity, attested by NIE, and revocable in real time.
5. Replay resistance. Each one-time secret and each operation nonce is consumed
   once.
6. Robustness. A minority of malicious or absent members cannot block a valid
   quorum from authorizing.
7. Compact and fast admission. Member contributions are small and the gate is
   cheap to verify, so high-frequency custody operations are practical.

Non-goal: TQ does not claim the whole system is information-theoretic or
unconditional. The threshold layer is information-theoretic; the deployed system
rests on stated computational and setup assumptions, enumerated in Section 4.

## 2. The construction

### 2.1 The one-time linear threshold gate (the promoted primitive)

Work over a prime field F_p. A custody set shares a secret vector
S = (s_1, ..., s_m) of m independent field elements, each Shamir-shared at
threshold t. Member j holds the vector of shares (s_1(x_j), ..., s_m(x_j)), where
s_l(.) is a degree t-1 polynomial with s_l(0) = s_l and x_j is the member's
evaluation point.

For an operation op, derive public coefficients c = (c_1, ..., c_m) = H2F(op),
where H2F is a hash to field that also folds in the CGA lineage and epoch and the
secret-vector identifier, so the coefficients are operation-specific and public.

Member j computes one field element, its contribution:

    y_j = sum over l of c_l * s_l(x_j)

This is member j's Shamir share of the authorization value

    A = sum over l of c_l * s_l

because g(.) = sum_l c_l * s_l(.) is itself a degree t-1 polynomial with
g(0) = A and g(x_j) = y_j. Any t contributions reconstruct A by Lagrange
interpolation at 0. Fewer than t reveal nothing about A, since they reveal
nothing about the underlying polynomials.

One-time bound. With m secrets, the secret vector supports at most m-1
authorizations before A values let an adversary solve the linear system for S.
The gate consumes a secret-vector identifier and rotates the vector before the
bound is reached. The affine case is m = 2, one safe use per coefficient
set. We parameterize m to the deployment and bind a refresh policy to the epoch.

This primitive is the promoted core: field arithmetic, Shamir split for setup and
test, the per-operation linear contribution, Lagrange reconstruction, and an
over-determined consistency check. It knows nothing about DSKAG, NIE, or chains.
The complete reference is `xsoc-tss-core_reference.rs`.

### 2.2 DSKAG-seeded setup

The secret vector is established once per epoch per custody set. Two real options,
both supported:

Dealer VSS. A custody authority deals the vector with Feldman or lattice-based
commitments so members verify their shares lie on the committed polynomials.
Suitable where a regulated custody authority already exists. Setup randomness is
DSKAG-derived, so re-dealing on refresh is deterministic and cheap.

Dealerless DKG. Each member contributes a sub-sharing whose randomness is
DSKAG-derived from its pairwise roots, and the joint polynomials are the sum of
contributions, verified by commitments. One interactive round at setup, none per
operation. DSKAG removes the need to exchange fresh randomness; it does not remove
the single combine-and-verify round, and this plan does not pretend it does.

DSKAG's contribution to both: deterministic per-member randomness from pairwise
roots, so setup and refresh need no fresh entropy exchange, and per-operation
contributions are non-interactive and reproducible.

### 2.3 On-chain verification, post-quantum

The gate reconstructs A from t contributions and must confirm A is the right value
for the operation without holding the secret. Use a linearly homomorphic,
post-quantum commitment to the secret vector, SIS or module-SIS based. At setup
the gate records Com(s_l) for each l. For an operation it checks

    Com(A) == sum over l of c_l * Com(s_l)

which holds by linearity of the commitment. Binding rests on SIS, which is
post-quantum. No pairing, no discrete log, nothing Shor breaks. Where the
deployment is designated-verifier and the commitment is not required, the gate
instead rests on attribution and consistency and freshness alone, per Section 2.4.

### 2.4 Member envelope, attribution, revocation

Each contribution travels in an envelope that binds operation, policy, epoch,
secret-vector id, member identity, the contribution y_j, and a commitment opening
where used. The envelope is authenticated with the 30-byte DSKAG authenticator
from QSIG main, keyed by the member's pairwise root, and attested by NIE so the
member device is bound and revocable through the NIE revocation listener.

This is a deliberate design choice. An asymmetric member attribution, such as a
hash-based signature, is publicly verifiable but multi-kilobyte and not revocable
without a registry write. The 30-byte symmetric authenticator here is compact,
post-quantum, and revocable in real time, at the cost of being designated-verifier.
For the public segment, Section 2.6 adds public verifiability without changing the
envelope.

### 2.5 Robust reconstruction and replay

The gate accepts up to t + 2e contributions and robustly reconstructs against up
to e corrupted shares by Reed-Solomon decoding, so a malicious minority cannot
block or steer authorization. It consumes the operation nonce and the
secret-vector id, rejecting any reuse, and records a compact receipt: policy id,
epoch, secret-vector id, operation nonce, member bitmap or count, the reconstructed
A or its commitment, and finality evidence. Retention profile is a deployment
choice, from full transcript to receipt only.

### 2.6 Optional public verifiability

Where verification must be public rather than designated-verifier, wrap the gate
in a transparent post-quantum proof, FRI or STARK based, proving that a quorum of
registered members produced consistent contributions whose reconstruction matches
the committed value, in zero knowledge of which members and which shares. This
gives public verifiability that a valid quorum approved, with member privacy that
per-member SLH-DSA attribution cannot offer, and it retires the BN254 and trusted
setup dependency entirely. This proof is optional and per-surface; designated
verifier deployments do not pay for it.

### 2.7 CGA lineage

The operation coefficients and the receipt bind CGA's X-ARC lineage and epoch, so
the authorization carries policy-rotation and audit lineage. CGA is the second
consumer that justifies promoting the primitive: it can use threshold
authorization for agent quorums without reimplementing the gate.

## 3. The data flow, end to end

1. Setup. The custody set establishes the secret vector by dealer VSS or
   dealerless DKG, DSKAG-seeded. The gate records the SIS commitments and the
   member registry.
2. Request. An operation op is proposed. Public coefficients c = H2F(op, lineage,
   epoch, vector id) are derived by anyone.
3. Contribute. Each approving member computes y_j, wraps it in a DSKAG-authenticated,
   NIE-attested envelope, and submits.
4. Reconstruct. The gate verifies envelopes, robustly reconstructs A from a quorum,
   and checks A against the commitment.
5. Authorize. On success the gate consumes the nonce and vector id, records the
   receipt, and releases the operation under finality.
6. Refresh. Before the one-time bound, the set rotates the secret vector.

## 4. Security argument, scoped

Information-theoretic, proven: threshold secrecy of the secret vector, and the
unpredictability of the one-time authorization value below threshold within the
m-1 use bound.

Post-quantum computational: member attribution from the DSKAG authenticator, EUF
under the HMAC PRF assumption; the on-chain commitment binding from SIS; the
optional public proof from a hash-based transparent system.

Setup and system assumptions: the DKG or VSS correctness and the honest-threshold
condition for dealerless setup; authenticated setup channels; BFT finality for
one-time consumption; the refresh policy enforced before the use bound.

Explicitly not claimed: that the system as a whole is information-theoretic or
unconditional. The threshold layer is; the deployment is not. This is the QSIG
B-01 calibration applied from the start.

## 5. Crate and module plan

Promoted primitive, new shared core:

    xsoc-tss-core
      field         prime-field helpers and hash-to-field
      shamir        split (setup and test), Lagrange reconstruction
      linear        per-operation contribution and reconstruction
      robust        Reed-Solomon consistency and error tolerance
      commit        SIS commitment interface and linear-homomorphism check
    Consumers: xsoc-sig-tq now, xsoc-sig-cga later, future modes.

TQ mode:

    xsoc-sig-tq
      setup         dealer VSS and dealerless DKG, DSKAG-seeded
      member        contribution and envelope build
      envelope      DSKAG authenticator plus NIE attestation binding
      gate          reconstruct, verify, consume, receipt
      wire          serialization
    Depends on xsoc-tss-core, xsoc-sig-core (DSKAG and wave_derive), nie
    (attestation and revocation), and reuses the 3P backend QsigCoreSign and
    WaveMac where the envelope authenticator is needed.

On-chain:

    contracts/XSOCQuorumGate.sol     EVM gate, SIS check, robust decode, receipt
    rail/quorum_validity             native consensus rule on the XSOC rail
    contracts/XSOCSignerRegistry.sol reused for member and commitment registration

Integration seams, all real bindings, none placeholders:

- `xsoc_sig_core::wave_derive` for DSKAG-seeded randomness and the envelope key,
  the same public wrapper the 3P corrections require.
- The NIE attestation and revocation API for the envelope.
- The SIS parameter set, chosen with the cryptographer of record.

## 6. Implementation plan, phased, no stubs at any phase

Each phase ships real cryptography. No mock backends, no stub verifiers, no
placeholder proofs, no `unimplemented!` or `todo!` outside test or an explicit
test-only feature. A disclosure-lint and no-stub CI gate enforces this on every
phase, as on QSIG and 3P.

Phase 0, specification and prior art. This document plus the formal security
argument. Timestamp on Zenodo. Gate: the construction is fully specified and the
claim boundary is written before any code.

Phase 1, the promoted core. `xsoc-tss-core` from the reference in this package:
field, Shamir, linear contribution, Lagrange reconstruction, over-determined
consistency, the SIS commitment interface. Gate: known-answer tests, a property
test that any t of n reconstruct and any t-1 do not, and the linear-homomorphism
test on the commitment.

Phase 2, setup. Dealer VSS and dealerless DKG with DSKAG-seeded randomness and
commitment verification. Gate: a malformed share is detected by commitment check;
a dishonest dealer is caught; refresh is deterministic and reproducible.

Phase 3, member and envelope. Contribution build, the DSKAG-authenticated and
NIE-attested envelope, revocation handling. Gate: a revoked member's envelope is
rejected; the envelope binds operation, policy, epoch, vector id, and member.

Phase 4, the gate. Robust reconstruction, the SIS check, nonce and vector-id
consumption, the receipt, on EVM and on the rail. Gate: a quorum authorizes; a
sub-quorum cannot; a replayed nonce is rejected; a corrupted minority does not
block reconstruction.

Phase 5, optional public proof. The transparent post-quantum proof of quorum
satisfaction with member privacy, for the public segment. Gate: a proof verifies
for a real quorum and a forged-quorum proof does not.

Phase 6, independent evaluation. The same evaluation discipline applied to DSKAG
and QSIG, with a dedicated harness: below-threshold forgery, replay, robustness,
attribution, commitment binding, and the one-time bound. Completion gate: the
below-threshold forgery construction fails, and only then is TQ represented as
functional.

## 7. Open problems and engineering risks

These parts carry real research and engineering risk:

1. Dealerless DKG with DSKAG-seeded randomness and post-quantum commitment
   verification. The math is known; the deterministic-randomness security
   argument and the commitment choice need care.
2. The one-time use bound and the refresh policy. m must be sized and refresh
   enforced before the bound, or the information-theoretic claim degrades.
3. Robust reconstruction parameters. The honest-share margin must hold under the
   adversary model.
4. The SIS commitment parameters and the on-chain verification cost. Post-quantum
   parameters are larger; the EVM cost and calldata must be measured.
5. The transparent proof cost, if the public segment needs it. Larger and more
   expensive than a pairing proof; justified only where public verifiability is
   required.

## 8. Design rationale

The threshold core is information-theoretic. The design choices around it favor a
compact, post-quantum, revocable member-authentication path and a deterministic
setup. Member attribution uses a 30-byte symmetric authenticator rather than a
multi-kilobyte asymmetric signature, so contributions stay small. Attestation and
revocation run through NIE, so membership is device-bound and revocable in real
time rather than fixed at registration. Setup and refresh randomness are
DSKAG-derived, so they are deterministic rather than requiring fresh interactive
secret sharing each cycle. The on-chain commitment is post-quantum. The cost,
stated plainly: symmetric attribution is designated-verifier, so public
verifiability is an optional proof layer rather than a built-in property. Where
the verifier is a known settlement venue or regulator that layer is not needed;
where anonymous public verifiability is required, the transparent proof of
Section 2.6 supplies it.

## 9. Availability

The xsoc-tss-core threshold primitive is published under Apache-2.0. Production
capability, including the DSKAG-rooted and NIE-attested backends and the
production module-SIS parameters, is available under license from XSOC. Contact
licensing@xsoccorp.com.
