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
        old_accumulator: (&'a Self::AccumulatorInstance,&'a Self::AccumulatorWitness), 
        input: (&'a Self::InputInstance,&'a Self::InputWitness) 
    ) -> Result<((Self::AccumulatorInstance, Self::AccumulatorWitness), Self::Proof), SynthesisError>;

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

#[cfg(test)]
pub mod test {
    use core::panic;
    use crate::{bd_as::{AccumulatorInstance, AccumulatorWitness, BDASAccumulationScheme}, AccumulationScheme};
    use ark_crypto_primitives::crh::{
        poseidon::{
            constraints::{CRHParametersVar, TwoToOneCRHGadget},
            TwoToOneCRH,
        },
        TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
    };
    use ark_ff::Field;
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_ed_on_bls12_381::Fr;
    use ark_ff::One;
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
    use crate::bd_as::r1cs_nark::{
        poseidon_parameters, R1CSNark
    };
    #[derive(Clone)]
    pub struct HashVerifyCirc {
        inp_wit_1: Fr,
        inp_wit_2: Fr,
        inp_hash: Fr,
        // old_accumulator_instance:AccumulatorInstance<Fr>,
        // old_accumulator_witness: AccumulatorWitness<Fr>,
        // new_accumulator_instance:AccumulatorInstance<Fr>,
        // new_accumulator_witness: AccumulatorWitness<Fr>,
        // input_proof: ASProof<Fr>,
        // accumulation_proof: Proof<Fr>,
        // acc_ivk: IndexVerifierKey<Fr>
    }
    impl ConstraintSynthesizer<Fr> for HashVerifyCirc {
        fn generate_constraints(
            self,
            cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
        ) -> ark_relations::r1cs::Result<()> {
            let poseidon_hash_params = <CRHParametersVar<_> as AllocVar<_, _>>::new_constant(
                ark_relations::ns!(cs, "poseidon_hash_params"),
                poseidon_parameters(),
            )?;
            let inp_hash =
                FpVar::new_input(ark_relations::ns!(cs, "inp_hash"), || Ok(self.inp_hash))?;
            let inp_wit_1 =
                FpVar::new_witness(ark_relations::ns!(cs, "inp_wit_1"), || Ok(self.inp_wit_1))?;
            let inp_wit_2 =
                FpVar::new_witness(ark_relations::ns!(cs, "inp_wit_2"), || Ok(self.inp_wit_2))?;
            let comp_hash = <TwoToOneCRHGadget<Fr> as TwoToOneCRHSchemeGadget<_, _>>::evaluate(
                &poseidon_hash_params,
                &inp_wit_1,
                &inp_wit_2,
            )?;

            // let comp_hash =  <CRHGadget<Fr> as CRHSchemeGadget<_,_>>::evaluate(poseidon_hash_params, inp_wit )?;
            comp_hash.enforce_equal(&inp_hash)?;

            // Verify the accumulation of the previous proof with the previous accumulator

            Ok(())
        }
    }

    fn test_template(
        num_iterations: usize
    ) -> bool {
        let mut inp_wit_1: Fr = <Fr as Field>::from_random_bytes(&[0_u8]).unwrap() * <Fr as One>::one();
        let mut inp_wit_2: Fr = <Fr as Field>::from_random_bytes(&[1_u8]).unwrap() * <Fr as One>::one();

        println!("inp_1: {:?}", inp_wit_1);
        println!("inp_2: {:?}", inp_wit_2);
        let mut inp_hash = <TwoToOneCRH<Fr> as TwoToOneCRHScheme>::evaluate(
            &poseidon_parameters(),
            inp_wit_1.clone(),
            inp_wit_2.clone(),
        )
        .unwrap();
        let mut hash_circ = HashVerifyCirc {
            inp_wit_1: inp_wit_1,
            inp_wit_2: inp_wit_2,
            inp_hash: inp_hash,
        };

        let mut rng = ark_std::test_rng();

        let pp = R1CSNark::<Fr>::setup();

        let Ok((ipk, ivk)) = R1CSNark::<Fr>::index(&pp, hash_circ.clone()) else {
            panic!("prover key not generated");
        };


        let mut old_acc_instance = AccumulatorInstance::zero(ipk.clone());
        let mut old_acc_witness = AccumulatorWitness::zero(ipk.clone());

        for i in 1..num_iterations {
            println!("Looping");
            let Ok((temp_ipk, _)) = R1CSNark::<Fr>::index(&pp, hash_circ.clone()) else {
                panic!("prover key not generated");
            };

            if temp_ipk.a == ipk.a {
                if temp_ipk.b == ipk.b {
                    if temp_ipk.c == ipk.c {
                        println!("Iteration {}: Matrices match", i);
                    }
                }
            }

            inp_hash = <TwoToOneCRH<Fr> as TwoToOneCRHScheme>::evaluate(
                &poseidon_parameters(),
                inp_wit_1.clone(),
                inp_wit_2.clone(),
            )
            .unwrap();

            hash_circ = HashVerifyCirc {
                inp_wit_1: inp_wit_1,
                inp_wit_2: inp_wit_2,
                inp_hash: inp_hash,
            };

            let proof = R1CSNark::<Fr>::prove(&ipk, hash_circ.clone(), Some(&mut rng)).unwrap();

            let Ok(((new_acc_instance, new_acc_witness), acc_proof)) = BDASAccumulationScheme::<Fr>::prove(
                &ipk,
                (&old_acc_instance, &old_acc_witness),
                (&proof.instance, &proof.witness)
            ) else {
                panic!["accumulation proof not generated"]
            };

            if !BDASAccumulationScheme::verify(
                &ivk, 
                &acc_proof, 
                (&old_acc_instance, &old_acc_witness), 
                (&new_acc_instance, &new_acc_witness), 
                (&proof.instance, &proof.witness)
            ).unwrap() {
                panic!["proof accumulation unsuccessful"]
            }

            old_acc_instance = new_acc_instance.clone();
            old_acc_witness = new_acc_witness.clone();

            inp_wit_1 = inp_wit_2.clone();
            inp_wit_2 = inp_hash.clone();
        }

        let decider_result = BDASAccumulationScheme::decide(
            &ivk, 
            (&old_acc_instance, &old_acc_witness)
        ).unwrap();

        if decider_result {
            return true
        } 

        false
    }

    #[test]
    pub fn test_case_1() {
        assert_eq!(test_template(1), true);
    }

    #[test]
    pub fn test_case_2() {
        assert_eq!(test_template(5), true);
    }

    #[test]
    pub fn test_case_3() {
        assert_eq!(test_template(10), true);
    }

    #[test]
    pub fn test_case_4() {
        assert_eq!(test_template(50), true);
    }

    #[test]
    pub fn test_case_5() {
        assert_eq!(test_template(100), true);
    }
}