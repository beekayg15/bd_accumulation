use ark_ff::Field;
use ark_ff::PrimeField;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, Matrix, OptimizationGoal, SynthesisError,
    SynthesisMode,
};
use ark_std::rand::RngCore;
use ark_std::vec::Vec;
use ark_std::{cfg_into_iter, marker::PhantomData};


mod data_structures;
pub use data_structures::*;

type R1CSResult<T> = Result<T, SynthesisError>;
pub(crate) const _CHALLENGE_SIZE: usize = 128;

///This is the proof for any x_{i+1} = f(x_i)
pub struct R1CSNark<F>
where
F: PrimeField
{
    _field: PhantomData<F>,
}

impl<F> R1CSNark<F>
where
F: PrimeField
{
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
            input,
            witness: witness.clone(),
        };

        let blinded_witness = witness; // Replace with finding merkle root for (input||witness)

        let commit_full_assgn = CommitmentFullAssignment {
            blinded_assignment: blinded_witness,
        };

        let proof = Proof {
            instance: full_assgn,
            witness: commit_full_assgn,
        };
        Ok(proof)
    }
    /// verifies a given proof and input using index verifier key
    pub fn verify(
        ivk: &IndexVerifierKey<F>,
        input: &[F],
        proof: &Proof<F>,
    ) -> bool {
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

/// multiply mat*[inp||wit]
pub(crate) fn matrix_vec_mul<F: Field>(matrix: &Matrix<F>, input: &[F], witness: &[F]) -> Vec<F> {
    ark_std::cfg_iter!(matrix)
        .map(|row| inner_prod(row, input, witness))
        .collect()
}
/// hadamard product
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

