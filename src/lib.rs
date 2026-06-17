//! xsoc-tss-core (reference for the promoted threshold primitive)
//!
//! The one-time linear threshold authorization gate that XSOC-QSIG/TQ is the
//! first consumer of, and that CGA and future modes will share. This file is the
//! complete, real math: prime-field helpers, Shamir split for setup and test, the
//! per-operation linear contribution, Lagrange reconstruction, and an
//! over-determined consistency check. It contains no mock and no stub.
//!
//! What is intentionally NOT here, because it belongs to other layers and must
//! not be faked:
//!   - The randomness source for setup is injected (`rng`), so this crate is
//!     source-agnostic. XSOC-QSIG/TQ injects an RNG seeded by
//!     xsoc_sig_core::wave_derive, making setup deterministic and DSKAG-rooted.
//!   - The post-quantum on-chain binding is the `LinearCommit` trait below, a
//!     real interface the gate programs against. A generic, parameter-injected
//!     reference instance lives in the `module_sis` module: the BDLOP module-SIS
//!     commitment, with ring degree, dimensions, norm bound, and CRS all supplied
//!     by the caller. The production instance, the ratified parameters and the
//!     DSKAG-seeded CRS, is selected in Phase 1 with the cryptographer of record
//!     and lives outside this crate. The reference fixes no instance, so it is the
//!     construction and not the stub a hardcoded parameter set would be.
//!
//! Field is generic over `ark_ff::PrimeField`. Dependencies: ark-ff, ark-std,
//! sha2, rand_core.
//!
//! License: LicenseRef-XSOC-Proprietary. CAGE 8ZXJ8. ECCN 5D002.C1.

#![forbid(unsafe_code)]

#[allow(unused_imports)] // UniformRand backs F::rand in shamir_split; the unused-import lint mis-reports it through arkworks supertraits.
use ark_ff::{PrimeField, UniformRand};
use rand_core::RngCore;
use sha2::{Digest, Sha256};

/// A member's evaluation point and its vector of shares, one per secret.
#[derive(Clone, Debug)]
pub struct MemberShares<F: PrimeField> {
    /// The member's Shamir x-coordinate (nonzero, distinct per member).
    pub x: F,
    /// Shares of each of the m secrets: shares[l] = s_l(x).
    pub shares: Vec<F>,
}

// -- Field helpers ---------------------------------------------------------

/// Hash to field with domain separation. Expands `data` into one field element
/// per call index. Used to derive public per-operation coefficients.
///
/// Uses reduction of a 256-bit digest modulo the field order. For fields where
/// the modest reduction bias matters, switch to rejection sampling; the call
/// sites here treat coefficients as public, so the bias is not security-bearing.
fn hash_to_field<F: PrimeField>(dst: &[u8], data: &[u8], index: u32) -> F {
    let mut h = Sha256::new();
    h.update((dst.len() as u64).to_be_bytes());
    h.update(dst);
    h.update((data.len() as u64).to_be_bytes());
    h.update(data);
    h.update(index.to_be_bytes());
    let digest = h.finalize();
    F::from_le_bytes_mod_order(&digest)
}

/// Derive the m public coefficients for an operation. `op_context` should already
/// fold in the operation, the CGA lineage and epoch, and the secret-vector id, so
/// the coefficients are unique per operation and per secret vector.
pub fn op_coefficients<F: PrimeField>(op_context: &[u8], m: usize) -> Vec<F> {
    const DST: &[u8] = b"XSOC-QSIG-TQ-v1:COEFF:";
    (0..m as u32).map(|i| hash_to_field::<F>(DST, op_context, i)).collect()
}

// -- Shamir split (setup and test) ----------------------------------------

/// Split one secret into `n` shares at threshold `t` over a random degree t-1
/// polynomial. Returns (x_j, s(x_j)) for x_j = 1..=n. Used by the dealer-VSS
/// setup path and by tests. The dealerless DKG composes per-member instances of
/// this with commitment verification; that protocol lives in xsoc-sig-tq.
pub fn shamir_split<F: PrimeField, R: RngCore>(
    secret: F,
    t: usize,
    n: usize,
    rng: &mut R,
) -> Vec<(F, F)> {
    assert!(t >= 1 && t <= n, "require 1 <= t <= n");
    // poly[0] = secret; poly[1..t] random.
    let mut poly = Vec::with_capacity(t);
    poly.push(secret);
    for _ in 1..t {
        poly.push(F::rand(rng));
    }
    (1..=n)
        .map(|i| {
            let x = F::from(i as u64);
            (x, eval_poly(&poly, x))
        })
        .collect()
}

/// Split a secret vector of length m into per-member share vectors.
pub fn deal_vector<F: PrimeField, R: RngCore>(
    secrets: &[F],
    t: usize,
    n: usize,
    rng: &mut R,
) -> Vec<MemberShares<F>> {
    let m = secrets.len();
    let mut members: Vec<MemberShares<F>> = (1..=n)
        .map(|i| MemberShares { x: F::from(i as u64), shares: Vec::with_capacity(m) })
        .collect();
    for &s in secrets {
        let col = shamir_split(s, t, n, rng);
        for (member, (_x, y)) in members.iter_mut().zip(col.into_iter()) {
            member.shares.push(y);
        }
    }
    members
}

fn eval_poly<F: PrimeField>(coeffs: &[F], x: F) -> F {
    // Horner.
    let mut acc = F::zero();
    for c in coeffs.iter().rev() {
        acc = acc * x + *c;
    }
    acc
}

// -- Per-operation contribution -------------------------------------------

/// A member's contribution for an operation: the linear combination of its share
/// vector with the public coefficients. This is the member's Shamir share of the
/// authorization value A = sum_l coeffs[l] * s_l.
pub fn member_contribution<F: PrimeField>(member: &MemberShares<F>, coeffs: &[F]) -> F {
    assert_eq!(member.shares.len(), coeffs.len(), "share and coefficient length mismatch");
    member
        .shares
        .iter()
        .zip(coeffs.iter())
        .fold(F::zero(), |acc, (s, c)| acc + (*s * *c))
}

// -- Reconstruction --------------------------------------------------------

/// Lagrange interpolation of the points through a degree t-1 polynomial,
/// evaluated at `at`. Points must have distinct x and number at least t.
pub fn interpolate_at<F: PrimeField>(points: &[(F, F)], at: F) -> F {
    let mut acc = F::zero();
    for (i, (xi, yi)) in points.iter().enumerate() {
        let mut num = F::one();
        let mut den = F::one();
        for (j, (xj, _)) in points.iter().enumerate() {
            if i != j {
                num *= at - *xj;
                den *= *xi - *xj;
            }
        }
        let li = num * den.inverse().expect("distinct x-coordinates give nonzero denominator");
        acc += *yi * li;
    }
    acc
}

/// Reconstruct the authorization value A from a quorum's contributions, the
/// (member_x, contribution) pairs. Uses the first available points; for robust
/// reconstruction against corrupted shares use `robust_reconstruct`.
pub fn reconstruct<F: PrimeField>(contributions: &[(F, F)], t: usize) -> F {
    assert!(contributions.len() >= t, "need at least t contributions");
    interpolate_at(&contributions[..t], F::zero())
}

/// Consistency check: every point beyond the first t must lie on the degree t-1
/// polynomial fixed by the first t. This catches an inconsistent or malformed
/// quorum. For true error correction against e corrupted shares with t + 2e
/// points, use a Reed-Solomon decoder (Berlekamp-Welch); this check is the
/// detection layer and the test oracle for it.
pub fn verify_consistency<F: PrimeField>(points: &[(F, F)], t: usize) -> bool {
    if points.len() < t {
        return false;
    }
    let base = &points[..t];
    points[t..]
        .iter()
        .all(|(x, y)| interpolate_at(base, *x) == *y)
}

// -- Post-quantum on-chain binding (the seam) ------------------------------

/// Linearly homomorphic, post-quantum commitment to the secret vector.
///
/// The gate records `commit(s_l)` for each secret at setup. For an operation with
/// public coefficients c, it checks the reconstructed A against
/// `combine(&[(c_l, commit(s_l))])`, which by linearity equals `commit(A)`.
/// Binding rests on module-SIS, which is post-quantum.
///
/// This is the contract. A generic, parameter-injected instance is provided in
/// the `module_sis` module, where the modulus, dimensions, norm bound, and CRS
/// are constructor arguments rather than hardcoded. The production instance, its
/// ratified parameters and DSKAG-seeded CRS, is selected in Phase 1 with the
/// cryptographer of record and lives outside this crate. A parameter-free
/// placeholder would be the stub that misleads the security analysis; a
/// parameterized construction is not.
pub trait LinearCommit<F: PrimeField> {
    /// An opaque commitment value.
    type Commitment: Clone + PartialEq;

    /// Commit to a single field element with its opening randomness.
    fn commit(&self, value: F, opening: &[u8]) -> Self::Commitment;

    /// Linear combination of commitments under public scalars, equal to the
    /// commitment of the same linear combination of the committed values.
    fn combine(&self, terms: &[(F, Self::Commitment)]) -> Self::Commitment;

    /// Verify that `c` commits to `value` under `opening`.
    fn verify(&self, c: &Self::Commitment, value: F, opening: &[u8]) -> bool;
}

pub mod module_sis;

// -- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr; // a concrete prime field for the tests
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([7u8; 32])
    }

    #[test]
    fn quorum_reconstructs_authorization_value() {
        let mut r = rng();
        let (t, n, m) = (3usize, 5usize, 8usize);
        let secrets: Vec<Fr> = (0..m).map(|_| Fr::rand(&mut r)).collect();
        let members = deal_vector(&secrets, t, n, &mut r);

        let coeffs = op_coefficients::<Fr>(b"op:withdraw:vault-9:epoch-12", m);

        // Direct authorization value A = sum_l c_l s_l.
        let a_direct = secrets
            .iter()
            .zip(coeffs.iter())
            .fold(Fr::from(0u64), |acc, (s, c)| acc + (*s * *c));

        // Any t members reconstruct A from their contributions.
        let contributions: Vec<(Fr, Fr)> = members[..t]
            .iter()
            .map(|mem| (mem.x, member_contribution(mem, &coeffs)))
            .collect();
        let a_recon = reconstruct(&contributions, t);

        assert_eq!(a_recon, a_direct, "t contributions must reconstruct A");
    }

    #[test]
    fn below_threshold_does_not_reconstruct() {
        let mut r = rng();
        let (t, n, m) = (3usize, 5usize, 4usize);
        let secrets: Vec<Fr> = (0..m).map(|_| Fr::rand(&mut r)).collect();
        let members = deal_vector(&secrets, t, n, &mut r);
        let coeffs = op_coefficients::<Fr>(b"op:test", m);

        let a_direct = secrets
            .iter()
            .zip(coeffs.iter())
            .fold(Fr::from(0u64), |acc, (s, c)| acc + (*s * *c));

        // t-1 contributions interpolated at 0 do not yield A (overwhelmingly).
        let few: Vec<(Fr, Fr)> = members[..t - 1]
            .iter()
            .map(|mem| (mem.x, member_contribution(mem, &coeffs)))
            .collect();
        let guess = interpolate_at(&few, Fr::from(0u64));
        assert_ne!(guess, a_direct, "t-1 shares must not reveal A");
    }

    #[test]
    fn any_quorum_subset_agrees() {
        let mut r = rng();
        let (t, n, m) = (4usize, 7usize, 6usize);
        let secrets: Vec<Fr> = (0..m).map(|_| Fr::rand(&mut r)).collect();
        let members = deal_vector(&secrets, t, n, &mut r);
        let coeffs = op_coefficients::<Fr>(b"op:rotate-keys", m);

        let all: Vec<(Fr, Fr)> = members
            .iter()
            .map(|mem| (mem.x, member_contribution(mem, &coeffs)))
            .collect();

        // First quorum and a different quorum reconstruct the same value.
        let a1 = reconstruct(&all[0..t], t);
        let a2 = reconstruct(&all[n - t..n], t);
        assert_eq!(a1, a2, "every quorum reconstructs the same A");
    }

    #[test]
    fn consistency_detects_a_corrupted_share() {
        let mut r = rng();
        let (t, n, m) = (3usize, 6usize, 5usize);
        let secrets: Vec<Fr> = (0..m).map(|_| Fr::rand(&mut r)).collect();
        let members = deal_vector(&secrets, t, n, &mut r);
        let coeffs = op_coefficients::<Fr>(b"op:settle", m);

        let mut points: Vec<(Fr, Fr)> = members
            .iter()
            .map(|mem| (mem.x, member_contribution(mem, &coeffs)))
            .collect();

        assert!(verify_consistency(&points, t), "honest quorum is consistent");

        // Corrupt one share past the first t and confirm detection.
        let last = points.len() - 1;
        points[last].1 += Fr::from(1u64);
        assert!(!verify_consistency(&points, t), "a corrupted share is detected");
    }
}
