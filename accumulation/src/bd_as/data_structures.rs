use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_crypto_primitives::merkle_tree::{Path, MerkleTree};
use crate::bd_as::r1cs_nark::{MerkleHashConfig, poseidon_parameters, IndexProverKey};
use ark_ff::PrimeField;
use ark_crypto_primitives::sponge::Absorb;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct AccumulatorInstance<F: PrimeField> {
    pub(crate) w: Vec<F>,
    pub(crate) err: Vec<F>,
    pub(crate) c: F,
}

impl<F: PrimeField> AccumulatorInstance<F> {
    pub(crate) fn zero(ipk: IndexProverKey<F>) -> Self {
        AccumulatorInstance{
            w: vec![F::zero(); ipk.index_info.num_variables],
            err: vec![F::zero(); ipk.index_info.num_variables],
            c: F::zero()
        }
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct AccumulatorWitness<F: PrimeField + Absorb> {
    pub(crate) blinded_w: F, //this is the root of a merkle tree for posiedon inner digest defined in
    //MerkleHashConfig
    pub(crate) blinded_err: F,
}

impl<F: PrimeField + Absorb> AccumulatorWitness<F> {
    pub(crate) fn zero(ipk: IndexProverKey<F>) -> Self {
        let hash_params = poseidon_parameters::<F>();

        let mut zero_mod = vec![[F::zero()]; 512];
        while !zero_mod.len().is_power_of_two() {
            zero_mod.push([F::zero()]);
        }

        let w_tree =
            MerkleTree::<MerkleHashConfig<F>>::new(
                &hash_params, 
                &hash_params, 
                zero_mod.clone()
            ).unwrap();

        let err_tree =
            MerkleTree::<MerkleHashConfig<F>>::new(
                &hash_params, 
                &hash_params, 
                zero_mod.clone()
            ).unwrap();

        AccumulatorWitness{
            blinded_w: w_tree.root(),
            blinded_err: err_tree.root(),
        }
    }
}

#[derive(Clone)]
pub struct Proof<F: PrimeField + Absorb> {
    pub(crate) acc_openings: Vec<Path<MerkleHashConfig<F>>>,
    pub(crate) new_acc_openings: Vec<Path<MerkleHashConfig<F>>>,
    pub(crate) input_openings: Vec<Path<MerkleHashConfig<F>>>,
    pub(crate) err_openings: Vec<Path<MerkleHashConfig<F>>>,
    pub(crate) new_err_openings: Vec<Path<MerkleHashConfig<F>>>,
    pub(crate) t_openings: Vec<Path<MerkleHashConfig<F>>>,
    pub(crate) blinded_t: F,
    pub(crate) t: Vec<F>,
}