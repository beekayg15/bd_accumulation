use std::marker::PhantomData;
use std::usize;

use ark_crypto_primitives::crh::poseidon::{TwoToOneCRH, CRH};
use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_crypto_primitives::merkle_tree::{Config, IdentityDigestConverter};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{One, PrimeField};
use ark_relations::r1cs::Matrix;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;

pub struct MerkleHashConfig<F: PrimeField> {
    _field_data: PhantomData<F>,
}

type CompressH<F> = TwoToOneCRH<F>;
impl<F: PrimeField + Absorb> Config for MerkleHashConfig<F> {
    type Leaf = [F];
    type LeafHash = CRH<F>;
    type LeafDigest = <CRH<F> as CRHScheme>::Output;
    type InnerDigest = <TwoToOneCRH<F> as TwoToOneCRHScheme>::Output;
    type LeafInnerDigestConverter = IdentityDigestConverter<Self::LeafDigest>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

/// dummy for public params
pub type PublicParameters = ();
// for an IVC this is the proof for x_{i+1} = f(x_i)
// a,b,c are r1cs constraint matrix for f
#[derive(Clone, Copy, CanonicalDeserialize, CanonicalSerialize)]
pub(crate) struct IndexInfo {
    pub(crate) num_constraints: usize,
    pub(crate) num_variables: usize,
    // pub(crate) num_instance_variables: usize,
    // pub(crate) matrices_hash: [u8; 32],
}

/// Prover key r1cs constraint matrices such that a.x + b.x = c.x
#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct IndexProverKey<F: PrimeField> {
    pub(crate) index_info: IndexInfo,
    pub(crate) a: Matrix<F>,
    pub(crate) b: Matrix<F>,
    pub(crate) c: Matrix<F>,
}
impl<F: PrimeField> IndexProverKey<F> {
    pub fn get_default(index_info: IndexInfo) -> Self {
        let n = index_info.num_variables + index_info.num_constraints;
        let mut zer: Vec<(F, usize)> = vec![];
        let mut def_m: Matrix<F> = vec![];
        for _i in 0..n {
            zer.push((F::ZERO, n));
        }
        for _i in 0..n {
            def_m.push(zer.clone());
        }
        let a: Matrix<F> = def_m.clone();
        let b: Matrix<F> = def_m.clone();
        let c: Matrix<F> = def_m.clone();
        IndexProverKey {
            index_info,
            a,
            b,
            c,
        }
    }
}

/// Verifier and prover key are same
pub type IndexVerifierKey<G> = IndexProverKey<G>;

/// an full assignment with input and witness
#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct FullAssignment<F: PrimeField> {
    pub(crate) input: Vec<F>,
    pub(crate) witness: Vec<F>,
}

impl<F: PrimeField> FullAssignment<F> {
    // pub(crate) fn zero(input_len: usize, witness_len: usize) -> Self {
    //     Self {
    //         input: vec![F::zero(); input_len],
    //         witness: vec![F::zero(); witness_len],
    //     }
    // }
}

// impl<F> Absorbable<F> for FullAssignment<F>
// where
//     F: PrimeField,
// {
//     fn to_sponge_bytes(&self) -> Vec<u8> {
//         collect_sponge_bytes!(F, &self.input, &self.witness)
//     }

//     fn to_sponge_field_elements(&self) -> Vec<CF> {
//         collect_sponge_field_elements!(&self.input, self.witness)
//     }
// }

/// commitment to the full (input,witness) vec (Merkle root)
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitmentFullAssignment<F: PrimeField + Absorb> {
    pub(crate) blinded_assignment: <TwoToOneCRH<F> as TwoToOneCRHScheme>::Output, // commitment to full assignment merkle root for tree
                                                                                  // with leaves = (input,witness)?
}

// impl<F: PrimeField> CommitmentFullAssignment<F> {
//     // pub(crate) fn zero(witness_len: usize) -> Self {
//     //     Self {
//     //         blinded_assignment: vec![F::zero(); witness_len],
//     //     }
//     // }
// }

/// a proof for a given circuit f with (input,witness) and merkle root of the same
#[derive(Clone)]
pub struct Proof<F: PrimeField + Absorb> {
    ///(input, witness)
    pub instance: FullAssignment<F>,
    ///merkle root for (input, witness),
    pub witness: CommitmentFullAssignment<F>,
}
