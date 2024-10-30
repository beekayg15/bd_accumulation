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
    type ProverKey: Clone + CanonicalDeserialize + CanonicalSerialize;
    type VerifierKey: Clone + CanonicalDeserialize + CanonicalSerialize;
    type DeciderKey: Clone + CanonicalDeserialize + CanonicalSerialize;

    fn prove<'a> (
        prover_key: &'a Self::ProverKey, 
        old_accumulators: (&'a Self::AccumulatorInstance,&'a Self::AccumulatorWitness), 
        input: (&'a Self::InputInstance,&'a Self::InputWitness) 
    ) -> Result<((&'a Self::AccumulatorInstance, &'a Self::AccumulatorWitness),&'a Self::Proof),SynthesisError>;

    fn verify<'a> (
        verifier_key: &'a Self::VerifierKey,
        proof: &Self::Proof, 
        old_accumulator: (&'a Self::AccumulatorInstance, &'a Self::AccumulatorWitness), 
        new_accumulator: (&'a Self::AccumulatorInstance, &'a Self::AccumulatorWitness), 
        input: (&'a Self::InputInstance, &'a Self::InputWitness),
    ) -> Result<bool,SynthesisError>;

    fn decide<'a> (
        decider_key: &'a Self::DeciderKey, 
        accumulator: (&'a Self::AccumulatorInstance,&'a Self::AccumulatorWitness) 
    ) -> Result<bool,SynthesisError>;

}