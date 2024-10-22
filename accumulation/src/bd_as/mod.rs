pub mod r1cs_nark;
use crate::bd_as::r1cs_nark::MerkleHashConfig;
use crate::AccumulationScheme;
use ark_crypto_primitives::merkle_tree::{MerkleTree, Path};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::marker::PhantomData;
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
struct AccumulatorInstance<F: PrimeField> {
    z: Vec<F>,
    err: Vec<F>,
    c: F,
}
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
struct AccumulatorWitness<F: PrimeField + Absorb> {
    merkle_root_z: F, //this is the root of a merkle tree for posiedon inner digest defined in
    //MerkleHashConfig
    merkle_root_err: F,
}

#[derive(Clone)]
struct Proof<F: PrimeField + Absorb> {
    opening_random_location: Vec<Path<MerkleHashConfig<F>>>,
}
#[derive(Clone)]
struct BDASAccumulationScheme<F: PrimeField + Absorb> {
    _field_data: PhantomData<F>,
}

impl<F: PrimeField + Absorb> AccumulationScheme<F> for BDASAccumulationScheme<F> {
    type AccumulatorInstance = AccumulatorInstance<F>;
    type AccumulatorWitness = AccumulatorWitness<F>;
    type Proof = Proof<F>;
}

