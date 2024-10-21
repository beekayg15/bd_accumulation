
use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::Matrix;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;

/// dummy for public params
pub type PublicParameters = ();
// for an IVC this is the proof for x_{i+1} = f(x_i)
// a,b,c are r1cs constraint matrix for f
#[derive(Clone, Copy)]
pub(crate) struct IndexInfo {
    pub(crate) num_constraints: usize,
    pub(crate) num_variables: usize,
    // pub(crate) num_instance_variables: usize,
    // pub(crate) matrices_hash: [u8; 32],
}

/// Prover key r1cs constraint matrices such that a.x + b.x = c.x
#[derive(Clone)]
pub struct IndexProverKey<F: PrimeField> {
    pub(crate) index_info: IndexInfo,
    pub(crate) a: Matrix<F>,
    pub(crate) b: Matrix<F>,
    pub(crate) c: Matrix<F>,
}

/// Verifier and prover key are same
pub type IndexVerifierKey<G> = IndexProverKey<G>;

/// an full assignment with input and witness
#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct FullAssignment<F: Field> {
    pub(crate) input: Vec<F>,
    pub(crate) witness: Vec<F>,
}

impl<F: Field> FullAssignment<F> {
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

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
/// commitment to the full (input,witness) vec (Merkle root)
pub struct CommitmentFullAssignment<F: Field> {
    pub(crate) blinded_assignment: Vec<F>, // commitment to full assignment merkle root for tree
                                           // with leaves = (input,witness)?
}

impl<F: Field> CommitmentFullAssignment<F> {
    // pub(crate) fn zero(witness_len: usize) -> Self {
    //     Self {
    //         blinded_assignment: vec![F::zero(); witness_len],
    //     }
    // }
}

/// a proof for a given circuit f with (input,witness) and merkle root of the same
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<F: Field> {
    ///(input, witness)
    pub instance: FullAssignment<F>,
    ///merkle root for (input, witness),
    pub witness: CommitmentFullAssignment<F>,
}

