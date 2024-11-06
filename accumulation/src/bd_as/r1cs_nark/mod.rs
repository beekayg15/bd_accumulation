use ark_crypto_primitives::merkle_tree::MerkleTree;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_ff::Zero;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint16::UInt16;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, Matrix, OptimizationGoal, SynthesisError,
    SynthesisMode,
};
use ark_std::ops::Mul;
use ark_std::rand::RngCore;
use ark_std::vec::Vec;
use ark_std::{cfg_into_iter, marker::PhantomData};

mod data_structures;
mod poseidon_config;
pub use data_structures::*;
pub use poseidon_config::*;

type R1CSResult<T> = Result<T, SynthesisError>;
pub(crate) const _CHALLENGE_SIZE: usize = 128;

///This is the proof for any x_{i+1} = f(x_i)
pub struct R1CSNark<F: PrimeField + Absorb> {
    _field: PhantomData<F>,
}

impl<F: PrimeField + Absorb> R1CSNark<F> {
    /// generates public params
    pub fn setup() -> PublicParameters {}
    /// generates index prover key and verifier key
    pub fn index<C: ConstraintSynthesizer<F>>(
        _pp: &PublicParameters,
        r1cs_instance: C,
    ) -> R1CSResult<(IndexProverKey<F>, IndexVerifierKey<F>)> {
        // let constraint_time = start_timer!(|| "Generating constraints");

        let ics = ConstraintSystem::new_ref();
        ics.set_optimization_goal(OptimizationGoal::Constraints);
        ics.set_mode(SynthesisMode::Setup);
        r1cs_instance.generate_constraints(ics.clone())?;

        // end_timer!(constraint_time);

        // let matrix_processing_time = start_timer!(|| "Processing matrices");
        ics.finalize();

        let matrices = ics.to_matrices().expect("should not be `None`");
        let (a, b, c) = (matrices.a, matrices.b, matrices.c);
        let (num_input_variables, num_witness_variables, num_constraints) = (
            ics.num_instance_variables(),
            ics.num_witness_variables(),
            ics.num_constraints(),
        );

        // end_timer!(matrix_processing_time);

        let num_variables = num_input_variables + num_witness_variables;
        let index_info = IndexInfo {
            num_variables,
            num_constraints,
            // num_instance_variables: num_input_variables,
            // matrices_hash,
        };
        let ipk = IndexProverKey {
            index_info,
            a,
            b,
            c,
        };
        let ivk = ipk.clone();
        Ok((ipk, ivk))
    }
    /// generates a proof for given Constraint synthesizer
    pub fn prove<C: ConstraintSynthesizer<F>>(
        ipk: &IndexProverKey<F>,
        r1cs: C,
        mut _rng: Option<&mut dyn RngCore>,
    ) -> R1CSResult<Proof<F>> {
        let pcs = ConstraintSystem::new_ref();
        pcs.set_optimization_goal(OptimizationGoal::Constraints);
        pcs.set_mode(ark_relations::r1cs::SynthesisMode::Prove {
            construct_matrices: false,
        });
        r1cs.generate_constraints(pcs.clone())?;

        pcs.finalize();
        let (input, witness, num_constraints) = {
            let pcs = pcs.borrow().unwrap();
            (
                pcs.instance_assignment.as_slice().to_vec(),
                pcs.witness_assignment.as_slice().to_vec(),
                pcs.num_constraints,
            )
        };

        let num_input_variables = input.len();
        let num_witness_variables = witness.len();
        let num_variables = num_input_variables + num_witness_variables;

        assert_eq!(ipk.index_info.num_variables, num_variables);
        assert_eq!(ipk.index_info.num_constraints, num_constraints);

        let full_assgn = FullAssignment {
            input: input.clone(),
            witness: witness.clone(),
        };
        let mut inp_wit: Vec<[F; 1]> = vec![];
        for i in input.iter() {
            inp_wit.push([i.clone()]);
        }
        for i in witness.iter() {
            inp_wit.push([i.clone()]);
        }
        while !inp_wit.len().is_power_of_two() {
            inp_wit.push([F::zero()]);
        }
        let hash_params = poseidon_config::poseidon_parameters::<F>();

        let witness_tree =
            MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, inp_wit).unwrap();

        let commit_full_assgn = CommitmentFullAssignment {
            blinded_assignment: witness_tree.root(),
        };

        let proof = Proof {
            instance: full_assgn,
            witness: commit_full_assgn,
        };
        Ok(proof)
    }

    /// verifies a given proof and input using index verifier key
    pub fn verify(ivk: &IndexVerifierKey<F>, input: &[F], proof: &Proof<F>) -> bool {
        let a_times_input_witness = matrix_vec_mul(&ivk.a, &input, &proof.instance.witness);
        let b_times_input_witness = matrix_vec_mul(&ivk.b, &input, &proof.instance.witness);
        let c_times_input_witness = matrix_vec_mul(&ivk.c, &input, &proof.instance.witness);

        // let mut comm_a = proof.first_msg.comm_a.into_projective();
        // let mut comm_b = proof.first_msg.comm_b.into_projective();
        // let mut comm_c = proof.first_msg.comm_c.into_projective();
        // if let Some(first_msg_randomness) = proof.first_msg.randomness.as_ref() {
        //     comm_a += first_msg_randomness.comm_r_a.mul(gamma);
        //     comm_b += first_msg_randomness.comm_r_b.mul(gamma);
        //     comm_c += first_msg_randomness.comm_r_c.mul(gamma);
        // }

        // let commit_time = start_timer!(|| "Reconstructing c_A, c_B, c_C commitments");
        // let reconstructed_comm_a = PedersenCommitment::commit(
        //     &ivk.ck,
        //     &a_times_blinded_witness,
        //     proof.second_msg.randomness.as_ref().map(|r| r.sigma_a),
        // );
        // let reconstructed_comm_b = PedersenCommitment::commit(
        //     &ivk.ck,
        //     &b_times_blinded_witness,
        //     proof.second_msg.randomness.as_ref().map(|r| r.sigma_b),
        // );
        // let reconstructed_comm_c = PedersenCommitment::commit(
        //     &ivk.ck,
        //     &c_times_blinded_witness,
        //     proof.second_msg.randomness.as_ref().map(|r| r.sigma_c),
        // );
        //
        // let a_equal = comm_a == reconstructed_comm_a.into_projective();
        // let b_equal = comm_b == reconstructed_comm_b.into_projective();
        // let c_equal = comm_c == reconstructed_comm_c.into_projective();
        // drop(c_times_blinded_witness);

        let had_prod: Vec<_> = cfg_into_iter!(a_times_input_witness)
            .zip(b_times_input_witness)
            .map(|(a, b)| a * b)
            .collect();
        // let reconstructed_had_prod_comm = PedersenCommitment::commit(
        //     &ivk.ck,
        //     &had_prod,
        //     proof.second_msg.randomness.as_ref().map(|r| r.sigma_o),
        // );

        // let mut had_prod_comm = proof.first_msg.comm_c.into_projective();
        // if let Some(first_msg_randomness) = proof.first_msg.randomness.as_ref() {
        //     had_prod_comm += first_msg_randomness.comm_1.mul(gamma);
        //     had_prod_comm += first_msg_randomness.comm_2.mul(gamma.square());
        // }
        // let had_prod_equal = had_prod_comm == reconstructed_had_prod_comm.into_projective();
        // add_to_trace!(|| "Verifier result", || format!(
        //     "A equal: {}, B equal: {}, C equal: {}, Hadamard Product equal: {}",
        //     a_equal, b_equal, c_equal, had_prod_equal
        // ));
        // a_equal & b_equal & c_equal & had_prod_equal
        return had_prod == c_times_input_witness;
    }
}
struct VerifierCircuitForR1CSNark<'a, F: PrimeField + Absorb> {
    ivk: IndexProverKey<F>,
    input: &'a [F],
    proof: Proof<F>,
}
impl<F: PrimeField + Absorb> ConstraintSynthesizer<F> for VerifierCircuitForR1CSNark<'_, F> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<F>,
    ) -> ark_relations::r1cs::Result<()> {
        let mut inp_wit: Vec<(FpVar<F>, UInt16<F>)> = vec![];
        for (ind, fp_val) in self.input.iter().enumerate() {
            inp_wit.push((
                FpVar::new_input(ark_relations::ns!(cs, "inp_val"), || Ok(fp_val))?,
                UInt16::new_input(ark_relations::ns!(cs, "inp_val_ind"), || {
                    Ok(u16::try_from(ind).unwrap())
                })?,
            ));
        }
        let inp_size = self.input.len();
        for (ind, fp_val) in self.proof.instance.witness.iter().enumerate() {
            inp_wit.push((
                FpVar::new_input(ark_relations::ns!(cs, "inp_val"), || Ok(fp_val))?,
                UInt16::new_input(ark_relations::ns!(cs, "inp_val_ind"), || {
                    Ok(u16::try_from(ind + inp_size).unwrap())
                })?,
            ));
        }
        let mut a: Vec<Vec<(FpVar<F>, UInt16<F>)>> = vec![];
        for row in self.ivk.a.iter() {
            let mut fp_row: Vec<(FpVar<F>, UInt16<F>)> = vec![];
            for val in row.iter() {
                fp_row.push((
                    FpVar::new_input(ark_relations::ns!(cs, "a"), || Ok(val.0))?,
                    UInt16::new_input(ark_relations::ns!(cs, "a_row_ind"), || {
                        Ok(u16::try_from(val.1).unwrap())
                    })?,
                ));
            }
            a.push(fp_row);
        }
        let mut b: Vec<Vec<(FpVar<F>, UInt16<F>)>> = vec![];
        for row in self.ivk.b.iter() {
            let mut fp_row: Vec<(FpVar<F>, UInt16<F>)> = vec![];
            for val in row.iter() {
                fp_row.push((
                    FpVar::new_input(ark_relations::ns!(cs, "b"), || Ok(val.0))?,
                    UInt16::new_input(ark_relations::ns!(cs, "b_row_ind"), || {
                        Ok(u16::try_from(val.1).unwrap())
                    })?,
                ));
            }
            b.push(fp_row);
        }
        let mut c: Vec<Vec<(FpVar<F>, UInt16<F>)>> = vec![];
        for row in self.ivk.c.iter() {
            let mut fp_row: Vec<(FpVar<F>, UInt16<F>)> = vec![];
            for val in row.iter() {
                fp_row.push((
                    FpVar::new_input(ark_relations::ns!(cs, "c"), || Ok(val.0))?,
                    UInt16::new_input(ark_relations::ns!(cs, "c_row_ind"), || {
                        Ok(u16::try_from(val.1).unwrap())
                    })?,
                ));
            }
            c.push(fp_row);
        }
        let mut a_mul_inp_wit: Vec<FpVar<F>> = vec![];
        for row in a.iter() {
            let mut val = FpVar::new_constant(
                ark_relations::ns!(cs, "val in a mul (inp,wit)"),
                <F as Zero>::zero(),
            )?;
            for (a_row_val, ind) in row.iter() {
                let ind_us: usize = ind.value()?.into();
                let (inp_wit_val, inp_wit_ind) = &inp_wit[ind_us];
                ind.enforce_equal(&inp_wit_ind)?;
                val += a_row_val.mul(inp_wit_val);
            }
            a_mul_inp_wit.push(val);
        }

        let mut b_mul_inp_wit: Vec<FpVar<F>> = vec![];
        for row in b.iter() {
            let mut val = FpVar::new_constant(
                ark_relations::ns!(cs, "val in a mul (inp,wit)"),
                <F as Zero>::zero(),
            )?;
            for (b_row_val, ind) in row.iter() {
                let ind_us: usize = ind.value()?.into();
                let (inp_wit_val, inp_wit_ind) = &inp_wit[ind_us];
                ind.enforce_equal(&inp_wit_ind)?;
                val += b_row_val.mul(inp_wit_val);
            }
            b_mul_inp_wit.push(val);
        }

        let mut c_mul_inp_wit: Vec<FpVar<F>> = vec![];
        for row in c.iter() {
            let mut val = FpVar::new_constant(
                ark_relations::ns!(cs, "val in a mul (inp,wit)"),
                <F as Zero>::zero(),
            )?;
            for (c_row_val, ind) in row.iter() {
                let ind_us: usize = ind.value()?.into();
                let (inp_wit_val, inp_wit_ind) = &inp_wit[ind_us];
                ind.enforce_equal(&inp_wit_ind)?;
                val += c_row_val.mul(inp_wit_val);
            }
            c_mul_inp_wit.push(val);
        }
        let mut had_prod_aiw_biw: Vec<FpVar<F>> = vec![];
        for (aiw_val, biw_val) in a_mul_inp_wit.iter().zip(b_mul_inp_wit.iter()) {
            had_prod_aiw_biw.push(aiw_val.mul(biw_val));
        }
        println!("had_prod: {:?}", had_prod_aiw_biw.value()?);
        println!("c inp wit: {:?}", c_mul_inp_wit.value()?);
        had_prod_aiw_biw.enforce_equal(&c_mul_inp_wit)?;
        Ok(())
    }
}
/// multiply mat*[inp||wit]
pub(crate) fn matrix_vec_mul<F: Field>(matrix: &Matrix<F>, input: &[F], witness: &[F]) -> Vec<F> {
    ark_std::cfg_iter!(matrix)
        .map(|row| inner_prod(row, input, witness))
        .collect()
}
/// inner product b/w two vectors
fn inner_prod<F: Field>(row: &[(F, usize)], input: &[F], witness: &[F]) -> F {
    let mut acc = F::zero();
    for &(ref coeff, i) in row {
        let tmp = if i < input.len() {
            input[i]
        } else {
            witness[i - input.len()]
        };

        acc += &(if coeff.is_one() { tmp } else { tmp * coeff });
    }
    acc
}

#[cfg(test)]
pub mod test {
    use core::panic;
    use std::borrow::Borrow;

    use super::*;
    use ark_crypto_primitives::crh::{
        poseidon::{
            constraints::{CRHParametersVar, TwoToOneCRHGadget},
            TwoToOneCRH,
        },
        TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
    };
    use ark_ed_on_bls12_381::Fr;
    use ark_ff::One;
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
    use ark_relations::r1cs::ConstraintSystemRef;
    #[derive(Clone)]
    pub struct HashVerifyCirc {
        inp_wit_1: Fr,
        inp_wit_2: Fr,
        inp_hash: Fr,
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
            // println!("comp_hash: {:?}", comp_hash);
            Ok(())
        }
    }
    #[test]
    pub fn test_r1cs_nark() {
        let inp_wit_1: Fr = <Fr as Field>::from_random_bytes(&[0_u8]).unwrap() * <Fr as One>::one();

        let inp_wit_2: Fr = <Fr as Field>::from_random_bytes(&[1_u8]).unwrap() * <Fr as One>::one();

        println!("inp_1: {:?}", inp_wit_1);
        println!("inp_2: {:?}", inp_wit_2);
        let inp_hash = <TwoToOneCRH<Fr> as TwoToOneCRHScheme>::evaluate(
            &poseidon_parameters(),
            inp_wit_1.clone(),
            inp_wit_2.clone(),
        )
        .unwrap();
        let hash_circ = HashVerifyCirc {
            inp_wit_1,
            inp_wit_2,
            inp_hash,
        };
        // hash_circ.clone().generate_constraints(cs.clone()).unwrap();
        // cs.finalize();
        // let (input, witness, num_constraints) = {
        //     let cs = cs.borrow().unwrap();
        //     (
        //         cs.instance_assignment.as_slice().to_vec(),
        //         cs.witness_assignment.as_slice().to_vec(),
        //         cs.num_constraints,
        //     )
        // };
        let pp = R1CSNark::<Fr>::setup();

        let Ok((ipk, ivk)) = R1CSNark::<Fr>::index(&pp, hash_circ.clone()) else {
            panic!("prover key not generated")
        };
        let mut rng = ark_std::test_rng();
        let Ok(proof) = R1CSNark::<Fr>::prove(&ipk, hash_circ, Some(&mut rng)) else {
            panic!["proof not generated"]
        };
        println!("PROOF GENERATED");
        let verified = R1CSNark::<Fr>::verify(&ivk, &[Fr::one(), inp_hash], &proof);
        assert_eq!(verified, true);
    }

    #[test]
    pub fn test_nark_verifier() {
        let inp_wit_1: Fr = <Fr as Field>::from_random_bytes(&[0_u8]).unwrap() * <Fr as One>::one();

        let inp_wit_2: Fr = <Fr as Field>::from_random_bytes(&[1_u8]).unwrap() * <Fr as One>::one();

        println!("inp_1: {:?}", inp_wit_1);
        println!("inp_2: {:?}", inp_wit_2);
        let inp_hash = <TwoToOneCRH<Fr> as TwoToOneCRHScheme>::evaluate(
            &poseidon_parameters(),
            inp_wit_1.clone(),
            inp_wit_2.clone(),
        )
        .unwrap();
        let hash_circ = HashVerifyCirc {
            inp_wit_1,
            inp_wit_2,
            inp_hash,
        };
        // hash_circ.clone().generate_constraints(cs.clone()).unwrap();
        // cs.finalize();
        // let (input, witness, num_constraints) = {
        //     let cs = cs.borrow().unwrap();
        //     (
        //         cs.instance_assignment.as_slice().to_vec(),
        //         cs.witness_assignment.as_slice().to_vec(),
        //         cs.num_constraints,
        //     )
        // };
        let pp = R1CSNark::<Fr>::setup();

        let Ok((ipk, ivk)) = R1CSNark::<Fr>::index(&pp, hash_circ.clone()) else {
            panic!("prover key not generated")
        };
        let mut rng = ark_std::test_rng();
        let Ok(proof) = R1CSNark::<Fr>::prove(&ipk, hash_circ, Some(&mut rng)) else {
            panic!["proof not generated"]
        };
        let cs: ConstraintSystemRef<Fr> = ConstraintSystem::new_ref();
        let verifier_cir = VerifierCircuitForR1CSNark {
            ivk: ivk.clone(),
            input: &[Fr::one(), inp_hash],
            proof,
        };
        println!("c: {:?}", ivk.clone().c);
        verifier_cir.generate_constraints(cs.clone()).unwrap();
        cs.finalize();
        let result = cs.is_satisfied().unwrap();
        assert_eq!(result, true);
    }
}
