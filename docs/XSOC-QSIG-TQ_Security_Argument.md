# XSOC-QSIG/TQ: Security Argument

Companion to the design and implementation plan. Public release. XSOC Corp.
Author: Richard Blech, ORCID 0009-0003-4540-2134. Companion to the XSOC-QSIG
specification, https://doi.org/10.5281/zenodo.19639166.

DSKAG, NIE, the wave engine, and the production module-SIS parameters are
proprietary trade secrets, not disclosed here, export-controlled under ECCN
5D002.C1, and available under license from XSOC. They appear only as black boxes,
as the named assumptions A1, A2, and A3. The threshold-layer results of Sections
4 and 5 are information-theoretic; the system as a whole is computationally secure
under the stated post-quantum assumptions, not information-theoretic or
unconditional. Document text: CC-BY-4.0.

This document states the security goals of the threshold quorum gate as games,
proves the information-theoretic claims, and reduces the computational claims to
named post-quantum assumptions. It holds the same discipline as the QSIG B-01
calibration: the threshold layer is information-theoretic, the deployed system is
not, and the boundary is drawn explicitly in Section 11.

## 1. The scheme, formally

Work over a prime field F_p. The custody set is M_1, ..., M_n with distinct
nonzero evaluation points x_1, ..., x_n in F_p, threshold t with 1 <= t <= n.

Secret vector. S = (s_1, ..., s_m) in F_p^m. Each s_l is shared by a uniformly
random degree t-1 polynomial

    f_l(X) = s_l + sum_{i=1}^{t-1} a_{l,i} X^i,   a_{l,i} uniform iid in F_p,

so f_l(0) = s_l. Member j holds the share vector sigma_j = (f_1(x_j), ...,
f_m(x_j)).

Operation. For an operation with context ctx, public coefficients
c = (c_1, ..., c_m) = H2F(ctx) in F_p^m, where ctx folds the operation, the CGA
lineage, the epoch, and the secret-vector identifier, and H2F is a hash to field
modeled as a random oracle.

Contribution. Member j returns

    y_j = <c, sigma_j> = sum_l c_l f_l(x_j) = g(x_j),

where g = sum_l c_l f_l has degree at most t-1 and g(0) = A = <c, S>. Any t
contributions reconstruct A by Lagrange interpolation at 0. The envelope E_j
authenticates (ctx, vector-id, M_j, y_j) with the 30-byte DSKAG authenticator
keyed by M_j's pairwise root and an NIE attestation of M_j's device.

Commitment. Com is a linearly homomorphic, computationally binding commitment.
At setup the gate records Com(s_l) for each l. For an operation the gate checks

    Com(A) == combine over l of (c_l, Com(s_l)),

which equals Com(<c, S>) by linearity. The gate also consumes (vector-id, nonce)
once, under finality.

Relationship to the affine special case. The degree-1, m = 2 instance with a
single use per coefficient set is the affine gate A = k1 x + k2. The construction
here is its generalization to degree t-1 and to m-1 uses per secret vector, with
attribution and the commitment forming a second barrier. The proofs below reduce
to the affine case at t = 2, m = 2.

## 2. Assumptions

- (A1) DSKAG authenticator EUF-CMA. For any quantum adversary B, the advantage
  Adv_euf_dskag(B) of forging a 30-byte authenticator under an unqueried key is
  negligible. Rests on the HMAC PRF assumption; symmetric, so quantum gives only
  a Grover square-root, addressed by parameter margin.
- (A2) NIE attestation soundness and revocation. An envelope is accepted only for
  a registered, non-revoked member, except with negligible Adv_nie.
- (A3) Commitment binding under module-SIS, and linear homomorphism. Opening one
  commitment two ways reduces to module-SIS, which is post-quantum. Advantage
  Adv_sis.
- (A4) Setup correctness. The VSS or dealerless DKG outputs a consistent Shamir
  sharing of S, under authenticated channels and the honest-threshold condition
  for the dealerless path, or an honest dealer for the VSS path.
- (A5) Finality. Consume-once of (vector-id, nonce) is enforced by BFT finality.
- (RO) H2F is a random oracle, so coefficient vectors for distinct operations are
  uniform and in general position except with negligible probability.

## 3. Security goals as games

Threshold secrecy. A coalition C of at most t-1 members, given their shares and
all public data, cannot distinguish S from uniform, and cannot predict A on a
fresh operation better than 1/p.

Quorum unforgeability. An adversary controlling a coalition C of c < t members,
with their keys and shares and oracle access to the gate, wins if the gate
authorizes an operation op* that fewer than t registered non-revoked members
approved.

Limited use. After k authorizations under one secret vector, a fresh
authorization on a linearly independent operation remains unpredictable to a
sub-threshold observer, provided k < m.

Robustness. A minority of corrupted contributions cannot block or alter the
authorization of an operation a quorum approved.

## 4. Threshold secrecy

Theorem 1. For any coalition C with |C| <= t-1, the view {sigma_j : j in C} is
statistically independent of S. Consequently, for any ctx with c = H2F(ctx)
nonzero, A = <c, S> is uniform over F_p given C's view.

Proof. Fix l. Conditioned on s_l, the polynomial f_l is uniform over degree t-1
polynomials with constant term s_l, that is, the coefficient vector
(a_{l,1}, ..., a_{l,t-1}) is uniform over F_p^{t-1}. The shares held by C are

    f_l(x_j) = s_l + sum_{i=1}^{t-1} a_{l,i} x_j^i,   j in C.

As a map from (a_{l,1}, ..., a_{l,t-1}) to (f_l(x_j) - s_l)_{j in C}, this is
multiplication by the |C| by (t-1) Vandermonde matrix on the distinct nonzero
points {x_j}. Since |C| <= t-1 and the points are distinct, that matrix has full
row rank, so the image is uniform over F_p^{|C|} and independent of s_l. The f_l
are independent across l, so the full view is independent of S. Independence of S
makes S uniform from C's posterior, hence A = <c, S> is uniform over F_p for
c nonzero. QED.

Corollary 1. A sub-threshold coalition guesses A for a fresh operation with
probability exactly 1/p.

## 5. Limited use

Theorem 2. Let ctx_1, ..., ctx_k be distinct operations with c_i = H2F(ctx_i),
and suppose the authorization values A_i = <c_i, S> are public. For a fresh
operation ctx* with c* = H2F(ctx*):

(a) if c* is not in span{c_1, ..., c_k}, then A* = <c*, S> is uniform over F_p
    given a sub-threshold coalition's view and the revealed A_i;
(b) if {c_1, ..., c_k} attains rank m, then S is determined and A* is fixed for
    every operation.

Proof. By Theorem 1 a sub-threshold coalition has no information about S beyond
the public linear constraints A_i = <c_i, S>. These confine S to an affine
subdomain of dimension m - rank{c_i}. In case (a) the new functional c* is
linearly independent of the constraints, so <c*, S> is an unconstrained linear
functional on the residual subdomain, hence uniform over F_p. In case (b) the
constraints determine S uniquely, so every A* is fixed. QED.

Corollary 2. Under (RO), k distinct operations give rank min(k, m) except with
negligible probability, so a secret vector retains a uniformly unpredictable
fresh authorization value while k < m. The refresh policy MUST rotate S before m
linearly independent authorizations. The affine gate is the case m = 2, one safe
use.

Remark. Theorem 2 concerns predictability of the authorization value. It is the
second barrier, not the first. Even when S becomes known, an adversary still
lacks the honest members' shares f_l(x_j) and so cannot produce their
contributions, and still lacks their authenticators and so cannot attribute them.
The first barrier is unforgeability, Section 6.

## 6. Quorum unforgeability

Theorem 3. Let an adversary control a coalition C of c < t members, with their
keys and shares, the public data, the wire, and q oracle queries to the gate.
The probability that the gate authorizes an operation approved by fewer than
t - c honest members is at most

    (t - c) * Adv_euf_dskag + Adv_nie + Adv_sis + q / p.

Proof. To authorize op*, the adversary must present at least t contributions that
(i) each carry a valid envelope for a distinct registered non-revoked member,
(ii) decode to a single A* on a degree t-1 polynomial, and (iii) reconstruct A*
matching the committed value for op*, with a fresh nonce.

The adversary holds c < t member keys. Producing t valid distinct envelopes
requires at least t - c envelopes for members it does not control. Each such
envelope is a forgery against the DSKAG authenticator or against NIE attestation;
by a hybrid over the at most t - c forged members, the probability of producing
them is at most (t - c) * Adv_euf_dskag + Adv_nie.

Condition on the adversary nonetheless presenting t envelopes. The contributions
at the honest members' points must equal f_l-consistent shares the adversary does
not hold. By Theorem 1 the correct contribution at an honest point is uniform
from the adversary's view, so a guessed contribution lies on the committed
polynomial with probability 1/p per gate query, contributing at most q / p. The
only alternative is to pass an inconsistent contribution set through the
commitment check, which opens Com(A*) to a value other than the linear
combination of the committed shares, a binding break bounded by Adv_sis.

Summing the three routes gives the stated bound. QED.

Corollary 3. With p >= 2^256 the q/p term is negligible for any feasible q, and
the bound is dominated by the post-quantum advantages Adv_euf_dskag, Adv_nie, and
Adv_sis.

## 7. Robustness

Theorem 4. The contributions of honest members are evaluations of the degree t-1
polynomial g at their points. Given t + 2e submitted contributions of which at
most e are corrupted, Berlekamp-Welch decoding recovers g uniquely, hence
recovers the correct A. Therefore a corrupted minority of size at most e can
neither block reconstruction nor steer it, provided at least t + 2e contributions
are gathered with at most e in error.

Proof. Standard Reed-Solomon decoding. The honest contributions are a Reed-Solomon
codeword of dimension t over the evaluation points; with at most e errors and at
least t + 2e total points, unique decoding holds, and the decoded message
evaluates at 0 to the unique correct A. QED.

## 8. Replay and attribution

Lemma 1, replay. The gate authorizes (vector-id, nonce) at most once. After
finality the pair is in the consumed set and any reuse is rejected, by (A5).

Lemma 2, attribution and revocation. By (A1) and (A2) an accepted contribution is
bound to a registered member. A member revoked through NIE before epoch e cannot
produce an envelope accepted at epoch e or later, except with probability Adv_nie,
since the epoch is bound in ctx and the attestation check fails for a revoked
device.

## 9. Composition

Theorem 5, main. The gate authorizes an operation op* only if at least t
registered non-revoked members contributed consistent shares for op* under the
current secret vector and a fresh nonce, except with probability at most

    (t - c) * Adv_euf_dskag + Adv_nie + Adv_sis + q / p,

against any quantum adversary controlling c < t members. The threshold secrecy of
Theorem 1 and the limited-use bound of Theorem 2 are information-theoretic and
hold unconditionally within the use bound. Robustness holds under the margin of
Theorem 4. Replay and attribution hold under Lemmas 1 and 2.

Proof. Compose Theorems 1 through 4 and Lemmas 1 and 2. Unforgeability gives the
quorum requirement and the stated bound. Threshold secrecy and limited use give
the information-theoretic second barrier on the authorization value. Robustness
gives liveness under a corrupted minority. Replay and attribution give freshness
and membership. QED.

## 10. Post-quantum justification

Each computational term is post-quantum. Adv_sis rests on module-SIS, a lattice
problem with no known quantum polynomial algorithm; Shor does not apply.
Adv_euf_dskag rests on the HMAC PRF assumption, a symmetric primitive against
which the best quantum attack is Grover, a square-root speedup addressed by
parameter margin, not Shor. The optional public-verifiability proof, where used,
is a transparent hash-based system, also post-quantum and free of trusted setup.
The information-theoretic results of Sections 4 and 5 hold against an unbounded
adversary and so are unaffected by quantum computation.

## 11. Scope of the claim

Information-theoretic, unconditional within the use bound: threshold secrecy
(Theorem 1) and the unpredictability of a fresh authorization value below
threshold (Theorem 2).

Post-quantum computational: member attribution (A1, A2), commitment binding (A3),
and the optional public proof.

Setup and system assumptions: VSS or DKG correctness with authenticated channels
and the honest-threshold condition (A4), and BFT finality for consume-once (A5).

Not claimed. The system as a whole is not information-theoretic or unconditional.
The threshold layer is; the deployment rests on the assumptions above. This is the
QSIG B-01 calibration applied from the outset, and the word information-theoretic
is confined to Theorems 1 and 2.

## 12. Parameters and the refresh policy

Field. p >= 2^256, so 1/p is negligible and the Grover margin on the symmetric
layer is comfortable.

Vector length m. Sized to the per-epoch authorization budget plus headroom, with
refresh enforced before m linearly independent authorizations per secret vector
(Corollary 2).

Threshold and fault tolerance. t and n by custody policy; the robustness margin e
requires gathering at least t + 2e contributions to tolerate e corrupted ones
(Theorem 4).

Commitment. Module-SIS parameters chosen for the target security level with the
cryptographer of record; the dimension, modulus, and norm bound set Adv_sis. The
on-chain verification cost and calldata follow from these and are measured in
Phase 4.

These parameters and the proofs of Sections 4 through 9 are the reference an
independent evaluator checks at Phase 6. The completion gate remains the
below-threshold forgery construction failing against the deployed gate.
