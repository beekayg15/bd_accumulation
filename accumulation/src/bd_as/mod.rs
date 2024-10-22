pub mod r1cs_nark;
use crate::AccumulationScheme;
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use ark_serialize::{CanonicalDeserialize,CanonicalSerialize};

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
struct AccumulatorInstance<F: PrimeField> {
    z: Vec<F>,
    err: Vec<F>,
    c: F
}
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
struct AccumulatorWitness<F: PrimeField> {
    merkle_root_z: Vec<F>,
    merkle_root_err: Vec<F>,
}

struct Proof<F: PrimeField> {
    opening_random_location: 

}
struct BDAS_AccumulationScheme<F: PrimeField> {
    _field_data: PhantomData<F>,
}

impl<F: PrimeField> AccumulationScheme<F> for BDAS_AccumulationScheme<F> {
    type AccumulatorInstance = AccumulatorInstance<F>;
    type AccumulatorWitness = AccumulatorWitness<F>;
    type Proof = ;
}