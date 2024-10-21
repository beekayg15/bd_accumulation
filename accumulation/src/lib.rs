use ark_ff::PrimeField;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};


pub mod data_structures;

pub mod bd_as;

pub trait AccumulationScheme<F: PrimeField> : Sized{
    type Proof: Clone;
    type AccumulatorInstance: Clone + CanonicalDeserialize + CanonicalSerialize;
    type AccumulatorWitness:  Clone + CanonicalDeserialize + CanonicalSerialize;
    type InputInstance: Clone + CanonicalDeserialize + CanonicalSerialize;
    type InputWitness: Clone + CanonicalDeserialize + CanonicalSerialize;

    fn prove<'a>(old_accumulators: Vec<(&'a Self::AccumulatorInstance,&'a Self::AccumulatorWitness)>, input: (&'a Self::InputInstance,&'a Self::InputWitness) ) 
    -> Result<((&'a Self::AccumulatorInstance, &'a Self::AccumulatorWitness),&'a Self::Proof),SynthesisError>;

    fn verfy<'a> (proof: &Self::Proof, accumulated_proofs: (&'a Self::AccumulatorInstance,&'a Self::AccumulatorWitness )) -> Result<bool,SynthesisError>;

    fn decide<'a> (accumulator: (&'a Self::AccumulatorInstance,&'a Self::AccumulatorWitness) ) -> Result<bool,SynthesisError>;

}