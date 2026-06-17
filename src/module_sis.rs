//! A concrete, parameter-injected module-SIS instance of [`crate::LinearCommit`].
//!
//! This is the BDLOP commitment over the ring R_q = Z_q[X]/(X^d + 1), where Z_q
//! is the field `F` the gate already works over. The commitment is
//!
//!   Com(s; r) = ( A1 * r ,  A2 * r + s )
//!
//! with A1 in R_q^{n x w}, A2 in R_q^{1 x w}, the message `s` embedded as a
//! constant polynomial, and the opening `r` a width-`w` vector of short ring
//! elements. It is additively homomorphic, and a public scalar `c` acts on a
//! commitment by acting on every ring coefficient, so
//!
//!   combine( [(c_l, Com(s_l; r_l))] ) = Com( sum c_l s_l ; sum c_l r_l )
//!
//! holds exactly. Binding is module-SIS on A1: two short openings of one
//! commitment give a short non-zero kernel vector of A1. Because binding rests
//! on a short-vector problem, `verify` enforces the norm bound; an opening whose
//! coefficients exceed the bound is rejected even if the algebra checks out. A
//! combination under large public scalars grows the opening past the bound and
//! is correctly refused, which is the intended boundary of the homomorphism.
//!
//! What is injected and not baked in:
//!   - the ring degree `d`, the height `n`, the width `w = n + k`, and the norm
//!     bound `beta` are constructor arguments;
//!   - the public matrices A1 and A2 are drawn from an injected RNG, so the CRS
//!     is supplied by the caller and this module fixes no specific instance.
//! The production parameters (the ratified d, q, dimensions, beta, and the CRS
//! seed) are selected with the cryptographer of record and live outside this
//! crate. This module is the real construction those parameters instantiate, not
//! a stub: it commits, combines, and verifies actual ring arithmetic.
//!
//! Multiplication here is the schoolbook negacyclic convolution, O(d^2). The
//! production instance replaces it with an NTT over a friendly q. The interface
//! and the results are identical; only the inner loop changes.

use crate::LinearCommit;
use ark_ff::{BigInteger, PrimeField};
#[allow(unused_imports)] // UniformRand backs F::rand in new_from_rng; the unused-import lint mis-reports it through arkworks supertraits.
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand_core::RngCore;

/// An element of R_q = Z_q[X]/(X^d + 1), stored as its `d` coefficients.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RingElem<F: PrimeField> {
    coeffs: Vec<F>,
}

impl<F: PrimeField> RingElem<F> {
    fn zero(d: usize) -> Self {
        RingElem { coeffs: vec![F::zero(); d] }
    }

    /// The message `s` lifted into the ring as the constant polynomial.
    fn constant(value: F, d: usize) -> Self {
        let mut coeffs = vec![F::zero(); d];
        coeffs[0] = value;
        RingElem { coeffs }
    }

    fn add(&self, other: &Self) -> Self {
        let coeffs = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        RingElem { coeffs }
    }

    /// Multiply every coefficient by a field scalar. This is how a public
    /// coefficient `c` acts on a commitment in `combine`.
    fn scale(&self, c: F) -> Self {
        RingElem { coeffs: self.coeffs.iter().map(|a| *a * c).collect() }
    }

    /// Negacyclic ring multiplication: X^d = -1, so terms that wrap past degree
    /// d - 1 fold back with a sign flip.
    fn mul(&self, other: &Self) -> Self {
        let d = self.coeffs.len();
        let mut res = vec![F::zero(); d];
        for i in 0..d {
            let ai = self.coeffs[i];
            if ai.is_zero() {
                continue;
            }
            for j in 0..d {
                let prod = ai * other.coeffs[j];
                let k = i + j;
                if k < d {
                    res[k] += prod;
                } else {
                    res[k - d] -= prod;
                }
            }
        }
        RingElem { coeffs: res }
    }

    /// True iff every coefficient, lifted to its centered representative in
    /// (-q/2, q/2], has absolute value at most `beta`.
    fn inf_norm_le(&self, beta: u64) -> bool {
        let bound = F::BigInt::from(beta);
        let mut half = F::MODULUS;
        half.div2();
        for x in &self.coeffs {
            let v = x.into_bigint();
            let mag = if v > half {
                // centered representative is negative; magnitude is q - v.
                let mut q = F::MODULUS;
                let _ = q.sub_with_borrow(&v);
                q
            } else {
                v
            };
            if mag > bound {
                return false;
            }
        }
        true
    }
}

/// A BDLOP commitment: the binding part `t0` and the message-carrying part `t1`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Commitment<F: PrimeField> {
    t0: Vec<RingElem<F>>,
    t1: RingElem<F>,
}

/// A parameter-injected module-SIS commitment scheme.
pub struct ModuleSisCommit<F: PrimeField> {
    d: usize,
    n: usize,
    w: usize,
    beta: u64,
    a1: Vec<Vec<RingElem<F>>>, // n x w
    a2: Vec<RingElem<F>>,      // 1 x w
}

impl<F: PrimeField> ModuleSisCommit<F> {
    /// Build a scheme by drawing the public CRS matrices from `rng`.
    ///
    /// - `d`   ring degree, a power of two;
    /// - `n`   binding height (module-SIS rank);
    /// - `k`   message/randomness slack, so the width is `w = n + k`;
    /// - `beta` the inclusive coefficient bound a valid opening must meet.
    pub fn new_from_rng<R: RngCore>(rng: &mut R, d: usize, n: usize, k: usize, beta: u64) -> Self {
        let w = n + k;
        let sample = |rng: &mut R| RingElem {
            coeffs: (0..d).map(|_| F::rand(rng)).collect::<Vec<_>>(),
        };
        let a1 = (0..n)
            .map(|_| (0..w).map(|_| sample(rng)).collect())
            .collect();
        let a2 = (0..w).map(|_| sample(rng)).collect();
        ModuleSisCommit { d, n, w, beta, a1, a2 }
    }

    /// Sample a fresh short opening (ternary coefficients) and return its bytes.
    pub fn sample_opening<R: RngCore>(&self, rng: &mut R) -> Vec<u8> {
        let r: Vec<RingElem<F>> = (0..self.w)
            .map(|_| RingElem {
                coeffs: (0..self.d).map(|_| ternary::<F, R>(rng)).collect(),
            })
            .collect();
        serialize_opening(&r)
    }

    /// Combine opening bytes the same way `combine` combines commitments, so the
    /// result opens the combined commitment. The caller holds the openings; the
    /// trait's `combine` only sees commitments.
    pub fn combine_openings(&self, terms: &[(F, &[u8])]) -> Vec<u8> {
        let mut acc: Vec<RingElem<F>> = vec![RingElem::zero(self.d); self.w];
        for (c, bytes) in terms {
            let r = deserialize_opening::<F>(bytes, self.w, self.d)
                .expect("combine_openings: malformed opening");
            for j in 0..self.w {
                acc[j] = acc[j].add(&r[j].scale(*c));
            }
        }
        serialize_opening(&acc)
    }

    fn commit_internal(&self, value: F, r: &[RingElem<F>]) -> Commitment<F> {
        let t0 = (0..self.n)
            .map(|i| {
                let mut row = RingElem::zero(self.d);
                for j in 0..self.w {
                    row = row.add(&self.a1[i][j].mul(&r[j]));
                }
                row
            })
            .collect();
        let mut t1 = RingElem::zero(self.d);
        for j in 0..self.w {
            t1 = t1.add(&self.a2[j].mul(&r[j]));
        }
        t1 = t1.add(&RingElem::constant(value, self.d));
        Commitment { t0, t1 }
    }
}

impl<F: PrimeField> LinearCommit<F> for ModuleSisCommit<F> {
    type Commitment = Commitment<F>;

    fn commit(&self, value: F, opening: &[u8]) -> Self::Commitment {
        let r = deserialize_opening::<F>(opening, self.w, self.d)
            .expect("commit: malformed opening");
        self.commit_internal(value, &r)
    }

    fn combine(&self, terms: &[(F, Self::Commitment)]) -> Self::Commitment {
        let mut t0 = vec![RingElem::zero(self.d); self.n];
        let mut t1 = RingElem::zero(self.d);
        for (c, com) in terms {
            for i in 0..self.n {
                t0[i] = t0[i].add(&com.t0[i].scale(*c));
            }
            t1 = t1.add(&com.t1.scale(*c));
        }
        Commitment { t0, t1 }
    }

    fn verify(&self, c: &Self::Commitment, value: F, opening: &[u8]) -> bool {
        let r = match deserialize_opening::<F>(opening, self.w, self.d) {
            Some(r) => r,
            None => return false,
        };
        // Binding rests on a short-vector problem, so an over-norm opening is
        // not a valid opening regardless of the algebra.
        if !r.iter().all(|ri| ri.inf_norm_le(self.beta)) {
            return false;
        }
        &self.commit_internal(value, &r) == c
    }
}

fn ternary<F: PrimeField, R: RngCore>(rng: &mut R) -> F {
    match rng.next_u32() % 3 {
        0 => F::zero(),
        1 => F::one(),
        _ => -F::one(),
    }
}

fn serialize_opening<F: PrimeField>(r: &[RingElem<F>]) -> Vec<u8> {
    let flat: Vec<F> = r.iter().flat_map(|re| re.coeffs.iter().copied()).collect();
    let mut bytes = Vec::new();
    flat.serialize_compressed(&mut bytes)
        .expect("serialize_opening: field elements always serialize");
    bytes
}

fn deserialize_opening<F: PrimeField>(bytes: &[u8], w: usize, d: usize) -> Option<Vec<RingElem<F>>> {
    let flat = Vec::<F>::deserialize_compressed(bytes).ok()?;
    if flat.len() != w * d {
        return None;
    }
    Some(
        flat.chunks(d)
            .map(|chunk| RingElem { coeffs: chunk.to_vec() })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    // Small, fast instance. Production d is 256 with an NTT; correctness of the
    // construction does not depend on the size, so the tests use d = 64.
    const D: usize = 64;
    const N: usize = 2;
    const K: usize = 4;
    const BETA: u64 = 16;

    fn scheme() -> (ModuleSisCommit<Fr>, ChaCha20Rng) {
        let mut crs_rng = ChaCha20Rng::from_seed([11u8; 32]);
        let scheme = ModuleSisCommit::<Fr>::new_from_rng(&mut crs_rng, D, N, K, BETA);
        let opening_rng = ChaCha20Rng::from_seed([22u8; 32]);
        (scheme, opening_rng)
    }

    #[test]
    fn commit_then_verify_round_trips() {
        let (s, mut rng) = scheme();
        let value = Fr::from(123456789u64);
        let opening = s.sample_opening(&mut rng);
        let c = s.commit(value, &opening);
        assert!(s.verify(&c, value, &opening));
    }

    #[test]
    fn verify_rejects_wrong_value() {
        let (s, mut rng) = scheme();
        let value = Fr::from(7u64);
        let opening = s.sample_opening(&mut rng);
        let c = s.commit(value, &opening);
        assert!(!s.verify(&c, value + Fr::from(1u64), &opening));
    }

    #[test]
    fn verify_rejects_wrong_opening() {
        let (s, mut rng) = scheme();
        let value = Fr::from(42u64);
        let opening = s.sample_opening(&mut rng);
        let c = s.commit(value, &opening);
        let other = s.sample_opening(&mut rng);
        assert!(!s.verify(&c, value, &other));
    }

    // combine over small public coefficients equals a commitment to the same
    // linear combination of the values, and the combined opening verifies it.
    #[test]
    fn homomorphism_holds_under_small_coefficients() {
        let (s, mut rng) = scheme();

        let values = [Fr::from(10u64), Fr::from(20u64), Fr::from(30u64)];
        let coeffs = [Fr::from(1u64), -Fr::from(1u64), Fr::from(1u64)]; // ternary, short
        let openings: Vec<Vec<u8>> = values.iter().map(|_| s.sample_opening(&mut rng)).collect();
        let commits: Vec<Commitment<Fr>> = values
            .iter()
            .zip(openings.iter())
            .map(|(v, o)| s.commit(*v, o))
            .collect();

        // commitment side
        let terms: Vec<(Fr, Commitment<Fr>)> =
            coeffs.iter().zip(commits.iter()).map(|(c, k)| (*c, k.clone())).collect();
        let combined = s.combine(&terms);

        // value side
        let combined_value: Fr = coeffs
            .iter()
            .zip(values.iter())
            .map(|(c, v)| *c * *v)
            .sum();

        // opening side
        let opening_terms: Vec<(Fr, &[u8])> =
            coeffs.iter().zip(openings.iter()).map(|(c, o)| (*c, o.as_slice())).collect();
        let combined_opening = s.combine_openings(&opening_terms);

        // the combined commitment opens to the combined value under the
        // combined opening
        assert!(s.verify(&combined, combined_value, &combined_opening));
        // and equals a direct commitment to the combined value
        assert_eq!(combined, s.commit(combined_value, &combined_opening));
    }

    // Large public coefficients push the combined opening past the norm bound.
    // The algebra still matches, but verify must refuse the over-norm opening.
    #[test]
    fn verify_refuses_over_norm_opening() {
        let (s, mut rng) = scheme();

        let v0 = Fr::from(5u64);
        let v1 = Fr::from(6u64);
        let o0 = s.sample_opening(&mut rng);
        let o1 = s.sample_opening(&mut rng);
        let c0 = s.commit(v0, &o0);
        let c1 = s.commit(v1, &o1);

        let big = Fr::from(1_000_000u64); // far above BETA
        let combined = s.combine(&[(big, c0), (Fr::from(1u64), c1)]);
        let combined_value = big * v0 + v1;
        let combined_opening =
            s.combine_openings(&[(big, o0.as_slice()), (Fr::from(1u64), o1.as_slice())]);

        // algebra matches: this is a true opening in the ring
        assert_eq!(combined, s.commit(combined_value, &combined_opening));
        // but it is over-norm, so verify refuses it
        assert!(!s.verify(&combined, combined_value, &combined_opening));
    }

    #[test]
    fn malformed_opening_is_rejected_not_panicked() {
        let (s, mut rng) = scheme();
        let value = Fr::from(1u64);
        let opening = s.sample_opening(&mut rng);
        let c = s.commit(value, &opening);
        assert!(!s.verify(&c, value, b"not a valid opening"));
        assert!(!s.verify(&c, value, &[]));
    }
}
