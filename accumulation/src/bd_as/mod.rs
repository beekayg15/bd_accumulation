pub mod r1cs_nark;

use crate::AccumulationScheme;
use ark_crypto_primitives::merkle_tree::MerkleTree;
use ark_crypto_primitives::prf::blake2s::Blake2s;
use ark_crypto_primitives::prf::PRF;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_relations::r1cs::SynthesisError;
use ark_std::cfg_into_iter;
use ark_std::marker::PhantomData;
use r1cs_nark::{
    matrix_vec_mul, poseidon_parameters, CommitmentFullAssignment, FullAssignment, IndexProverKey,
    IndexVerifierKey, MerkleHashConfig
};


mod data_structures;
pub use data_structures::*;
mod reed_solomon;
pub use reed_solomon::*;

#[derive(Clone)]
pub struct BDASAccumulationScheme<F: PrimeField + Absorb> {
    _field_data: PhantomData<F>,
}

fn bytes_to_field_vec<F: PrimeField>(bytes: [u8; 32]) -> Vec<F> {
    let bits_per_elem = F::MODULUS_BIT_SIZE as usize;
    let bytes_per_elem = (bits_per_elem + 7) / 8; // Convert bits to bytes, rounding up
    let mut result = vec![];

    // Iterate over chunks of the byte array and convert each chunk to a field element
    for chunk in bytes.chunks(bytes_per_elem) {
        // Convert the byte array to a BigInteger and then to a field element
        let elem = F::from_be_bytes_mod_order(chunk);
        result.push(elem);
    }

    result
}

fn field_vec_to_fixed_bytes<F: PrimeField>(field_elems: Vec<F>) -> [u8; 32] {
    let mut byte_vec = Vec::new();

    // Calculate minimum number of elements needed
    let bits_needed = 256; // 32 bytes * 8 bits/byte
    let elements_needed =
        (bits_needed + F::MODULUS_BIT_SIZE as usize - 1) / F::MODULUS_BIT_SIZE as usize;

    // Take only the minimum required elements
    let field_elems_truncated = field_elems.into_iter().take(elements_needed);

    // Convert each field element to bytes using into_bigint().to_le_bytes() and append it to byte_vec
    for elem in field_elems_truncated {
        let elem_bytes = elem.into_bigint().to_bytes_le();
        byte_vec.extend_from_slice(&elem_bytes);
    }

    // Truncate or pad to exactly 32 bytes
    let mut result = [0u8; 32];
    let copy_len = byte_vec.len().min(32);
    result[..copy_len].copy_from_slice(&byte_vec[..copy_len]);

    result
}

fn get_randomness<F: PrimeField>(input_witness: Vec<F>, accumulator_witness: Vec<F>) -> Vec<F> {
    let seed: [u8; 32] = field_vec_to_fixed_bytes(input_witness);
    let inp: [u8; 32] = field_vec_to_fixed_bytes(accumulator_witness);
    bytes_to_field_vec(Blake2s::evaluate(&seed, &inp).unwrap())
}

fn get_random_indices<F: PrimeField>(
    number_indices: usize, 
    input_witness: Vec<F>, 
    accumulator_witness: Vec<F>,
    max_index: usize,
) -> Vec<usize> {
    let seed: [u8; 32] = field_vec_to_fixed_bytes(input_witness);
    let mut inp: [u8; 32] = field_vec_to_fixed_bytes(accumulator_witness);
    let mut r:Vec<F> = bytes_to_field_vec(Blake2s::evaluate(&seed, &inp).unwrap());

    let mut indices: Vec<usize> = vec![];
    let mut _bytes= [0u8; 8];

    inp = field_vec_to_fixed_bytes(r.clone());

    for _ in 0 .. number_indices {
        r = bytes_to_field_vec(Blake2s::evaluate(&seed, &inp).unwrap());
        inp = field_vec_to_fixed_bytes(r.clone());
        _bytes.clone_from_slice(&inp[0 .. 8]);
        indices.push(usize::from_be_bytes(_bytes) % max_index);
    }

    indices
}

impl<F: PrimeField + Absorb> AccumulationScheme<F> for BDASAccumulationScheme<F> {
    type AccumulatorInstance = AccumulatorInstance<F>;
    type AccumulatorWitness = AccumulatorWitness<F>;
    type Proof = Proof<F>;
    type InputInstance = FullAssignment<F>;
    type InputWitness = CommitmentFullAssignment<F>;
    type ProverKey = IndexProverKey<F>;
    type VerifierKey = IndexVerifierKey<F>;
    type DeciderKey = IndexVerifierKey<F>;

    fn prove<'a>(
        prover_key: &'a Self::ProverKey,
        old_accumulator: (&'a Self::AccumulatorInstance, &'a Self::AccumulatorWitness),
        input: (&'a Self::InputInstance, &'a Self::InputWitness),
    ) -> Result<
        (
            (Self::AccumulatorInstance, Self::AccumulatorWitness),
            Self::Proof,
        ),
        SynthesisError,
    > {
        // Using Fiat-Shamir to compute randomness of the linear combination
        let r: F = get_randomness(
            vec![input.1.blinded_assignment],
            vec![old_accumulator.1.blinded_w],
        )[0];

        let (input_instance, input_witness) = input;
        let mut input_assignment = input_instance.input.clone();
        input_assignment.extend(input_instance.witness.clone());

        let num_input_variables = input_instance.input.len();
        let num_witness_variables = input_instance.witness.len();
        let num_variables = num_witness_variables + num_input_variables;

        assert_eq!(prover_key.index_info.num_variables, num_variables);

        let (acc_instance, acc_witness) = old_accumulator;
        let num_acc_variables = acc_instance.w.len();

        assert_eq!(prover_key.index_info.num_variables, num_acc_variables);
        assert_eq!(prover_key.index_info.num_variables, acc_instance.err.len());

        let mut az = matrix_vec_mul(&prover_key.a, &input_instance.input, &input_instance.witness);
        let mut bz = matrix_vec_mul(&prover_key.b, &input_instance.input, &input_instance.witness);
        let mut cz = matrix_vec_mul(&prover_key.c, &input_instance.input, &input_instance.witness);

        let mut aw = matrix_vec_mul(&prover_key.a, &acc_instance.w, &vec![]);
        let mut bw = matrix_vec_mul(&prover_key.b, &acc_instance.w, &vec![]);
        let mut cw = matrix_vec_mul(&prover_key.c, &acc_instance.w, &vec![]);

        while az.len() < num_acc_variables  {
            az.push(F::zero());
            bz.push(F::zero());
            cz.push(F::zero());
            aw.push(F::zero());
            bw.push(F::zero());
            cw.push(F::zero());
        }

        let azbw = had_product(&az, &bw);
        let awbz = had_product(&aw, &bz);

        let t = sub_vectors(
            &add_vectors(&azbw, &awbz),
            &add_vectors(&cw, &scalar_mult(&acc_instance.c, &cz)),
        );

        let t_code = RSCode::encode(t.clone(), 512).code;

        let mut t_modified: Vec<[F; 1]> = vec![];
        for &i in t_code.iter() {
            t_modified.push([i.clone()]);
        }
        while !t_modified.len().is_power_of_two() {
            t_modified.push([F::zero()]);
        }

        let w_code = RSCode::encode(acc_instance.w.clone(), 512).code;

        let mut w_modified: Vec<[F; 1]> = vec![];
        for &i in w_code.iter() {
            w_modified.push([i.clone()]);
        }
        while !w_modified.len().is_power_of_two() {
            w_modified.push([F::zero()]);
        }

        let z_code = RSCode::encode(input_assignment.clone(), 512).code;

        let mut z_modified: Vec<[F; 1]> = vec![];
        for &i in z_code.iter() {
            z_modified.push([i.clone()]);
        }
        while !z_modified.len().is_power_of_two() {
            z_modified.push([F::zero()]);
        }

        let err_code = RSCode::encode(acc_instance.err.clone(), 512).code;

        let mut err_modified: Vec<[F; 1]> = vec![];
        for &i in err_code.iter() {
            err_modified.push([i.clone()]);
        }
        while !err_modified.len().is_power_of_two() {
            err_modified.push([F::zero()]);
        }

        let hash_params = poseidon_parameters::<F>();

        let t_tree =
            MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, t_modified).unwrap();

        let w_tree =
            MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, w_modified).unwrap();

        let z_tree =
            MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, z_modified.clone()).unwrap();

        let err_tree =
            MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, err_modified)
                .unwrap();

        assert_eq!(err_tree.root(), acc_witness.blinded_err);
        assert_eq!(w_tree.root(), acc_witness.blinded_w);
        assert_eq!(z_tree.root(), input_witness.blinded_assignment);

        let blinded_t = t_tree.root();

        let new_w = add_vectors(&acc_instance.w, &scalar_mult(&r, &input_assignment));

        let new_err = add_vectors(&acc_instance.err, &scalar_mult(&r, &t));

        let new_acc_instance = AccumulatorInstance {
            w: new_w.clone(),
            err: new_err.clone(),
            c: acc_instance.c + r,
        };

        let new_err_code = RSCode::encode(new_err.clone(), 512).code;

        let mut new_err_modified: Vec<[F; 1]> = vec![];
        for &i in new_err_code.iter() {
            new_err_modified.push([i]);
        }
        while !new_err_modified.len().is_power_of_two() {
            new_err_modified.push([F::zero()]);
        }

        let new_w_code = RSCode::encode(new_w.clone(), 512).code;

        let mut new_w_modified: Vec<[F; 1]> = vec![];
        for &i in new_w_code.iter() {
            new_w_modified.push([i.clone()]);
        }
        while !new_w_modified.len().is_power_of_two() {
            new_w_modified.push([F::zero()]);
        }

        let new_w_tree =
            MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, new_w_modified)
                .unwrap();

        let new_err_tree =
            MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, new_err_modified)
                .unwrap();

        let new_acc_witness = AccumulatorWitness {
            blinded_err: new_err_tree.root(),
            blinded_w: new_w_tree.root(),
        };

        let mut acc_openings = vec![];
        let mut new_acc_openings = vec![];
        let mut input_openings = vec![];
        let mut err_openings = vec![];
        let mut new_err_openings = vec![];
        let mut t_openings = vec![];

        let _indices = get_random_indices(
            16, 
            vec![input.1.blinded_assignment],
            vec![old_accumulator.1.blinded_w],
            512
        );

        for i in _indices {
            acc_openings.push(w_tree.generate_proof(i).unwrap());
            new_acc_openings.push(new_w_tree.generate_proof(i).unwrap());
            input_openings.push(z_tree.generate_proof(i).unwrap());
            err_openings.push(err_tree.generate_proof(i).unwrap());
            new_err_openings.push(new_err_tree.generate_proof(i).unwrap());
            t_openings.push(t_tree.generate_proof(i).unwrap());
        }

        let proof = Proof {
            acc_openings: acc_openings,
            new_acc_openings: new_acc_openings,
            input_openings: input_openings,
            err_openings: err_openings,
            new_err_openings: new_err_openings,
            t_openings: t_openings,
            blinded_t: blinded_t,
            t: t,
        };

        Ok(((new_acc_instance, new_acc_witness), proof))
    }

    fn verify<'a>(
        verifier_key: &'a Self::VerifierKey,
        proof: &Self::Proof,
        old_accumulator: (&'a Self::AccumulatorInstance, &'a Self::AccumulatorWitness),
        new_accumulator: (&'a Self::AccumulatorInstance, &'a Self::AccumulatorWitness),
        input: (&'a Self::InputInstance, &'a Self::InputWitness),
    ) -> Result<bool, SynthesisError> {
        let input_openings = &proof.input_openings;
        let acc_openings = &proof.acc_openings;
        let new_acc_openings = &proof.new_acc_openings;
        let t_openings = &proof.t_openings;
        let err_openings = &proof.err_openings;
        let new_err_openings = &proof.new_err_openings;

        if input_openings.len() != acc_openings.len() {
            return Ok(false);
        } else if input_openings.len() != new_acc_openings.len() {
            return Ok(false);
        }

        let hash_params = poseidon_parameters::<F>();

        let (input_instance, input_witness) = input;
        let (acc_instance, acc_witness) = old_accumulator;
        let (new_acc_instance, new_acc_witness) = new_accumulator;
        let t = &proof.t;

        let mut counter = 0;
        let mut input_assignment = input_instance.input.clone();
        input_assignment.extend(input_instance.witness.clone());

        let new_w_code = RSCode::encode(new_acc_instance.w.clone(), 512).code;
        let new_err_code = RSCode::encode(new_acc_instance.err.clone(), 512).code;
        let err_code = RSCode::encode(acc_instance.err.clone(), 512).code;
        let z_code = RSCode::encode(input_assignment.clone(), 512).code;
        let w_code = RSCode::encode(acc_instance.w.clone(), 512).code;
        let t_code = RSCode::encode(t.clone(), 512).code;

        let opening_indexes = get_random_indices(
            16,
            vec![input.1.blinded_assignment],
            vec![old_accumulator.1.blinded_w],
            512
        );

        for opening in input_openings {
            if !opening.verify(
                &hash_params,
                &hash_params,
                &input_witness.blinded_assignment,
                [z_code[opening_indexes[counter]]],
            ).unwrap() {
                return Ok(false);
            }
            counter += 1;
        }

        counter = 0;
        for opening in acc_openings {
            if !opening.verify(
                &hash_params,
                &hash_params,
                &acc_witness.blinded_w,
                [w_code[opening_indexes[counter]]],
            ).unwrap() {
                return Ok(false);
            }
            counter += 1;
        }

        counter = 0;
        for opening in new_acc_openings {
            if !opening.verify(
                &hash_params,
                &hash_params,
                &new_acc_witness.blinded_w,
                [new_w_code[opening_indexes[counter]]],
            ).unwrap() {
                return Ok(false);
            }
            counter += 1;
        }

        counter = 0;
        for opening in t_openings {
            if !opening.verify(
                &hash_params, 
                &hash_params, 
                &proof.blinded_t, 
                [t_code[opening_indexes[counter]]]
            ).unwrap() {
                return Ok(false);
            }
            counter += 1;
        }

        counter = 0;
        for opening in err_openings {
            if !opening.verify(
                &hash_params,
                &hash_params,
                &acc_witness.blinded_err,
                [err_code[opening_indexes[counter]]],
            ).unwrap() {
                return Ok(false);
            }
            counter += 1;
        }

        counter = 0;
        for opening in new_err_openings {
            if !opening.verify(
                &hash_params,
                &hash_params,
                &new_acc_witness.blinded_err,
                [new_err_code[opening_indexes[counter]]],
            ).unwrap() {
                return Ok(false);
            }
            counter += 1;
        }

        let r: F = get_randomness(
            vec![input.1.blinded_assignment],
            vec![old_accumulator.1.blinded_w],
        )[0];

        if acc_instance.c + r != new_acc_instance.c {
            return Ok(false);
        }

        for i in opening_indexes {
            if new_w_code[i] != w_code[i] + r * z_code[i] {
                return Ok(false);
            }

            if new_err_code[i] != err_code[i] + r * t_code[i] {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn decide<'a>(
        decider_key: &'a Self::DeciderKey,
        accumulator: (&'a Self::AccumulatorInstance, &'a Self::AccumulatorWitness),
    ) -> Result<bool, SynthesisError> {
        let (instance, witness) = accumulator;

        let mut aw = matrix_vec_mul(&decider_key.a, &instance.w, &vec![]);
        let mut bw = matrix_vec_mul(&decider_key.b, &instance.w, &vec![]);
        let mut cw = matrix_vec_mul(&decider_key.c, &instance.w, &vec![]);

        while aw.len() < decider_key.index_info.num_variables {
            aw.push(F::zero());
            bw.push(F::zero());
            cw.push(F::zero());
        }

        let w_code = RSCode::encode(instance.w.clone(), 512).code;
        let err_code = RSCode::encode(instance.err.clone(), 512).code;

        let mut w_modified: Vec<[F; 1]> = vec![];
        for i in w_code.iter() {
            w_modified.push([i.clone()]);
        }
        while !w_modified.len().is_power_of_two() {
            w_modified.push([F::zero()]);
        }

        let mut err_modified: Vec<[F; 1]> = vec![];
        for i in err_code.iter() {
            err_modified.push([i.clone()]);
        }
        while !err_modified.len().is_power_of_two() {
            err_modified.push([F::zero()]);
        }

        let hash_params = poseidon_parameters::<F>();

        let w_tree =
            MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, w_modified).unwrap();

        let err_tree =
            MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, err_modified)
                .unwrap();

        assert_eq!(w_tree.root(), witness.blinded_w);
        assert_eq!(err_tree.root(), witness.blinded_err);

        let lhs = had_product(&aw, &bw);

        let rhs = add_vectors(&instance.err, &scalar_mult(&instance.c, &cw));
        
        if lhs == rhs {
            return Ok(true)
        }
        Ok(false)
    }
}

fn add_vectors<F: Field>(vec_a: &Vec<F>, vec_b: &Vec<F>) -> Vec<F> {
    let sum = cfg_into_iter!(vec_a)
        .zip(vec_b)
        .map(|(a, b)| (*a) + (*b))
        .collect();

    sum
}

fn sub_vectors<F: Field>(vec_a: &Vec<F>, vec_b: &Vec<F>) -> Vec<F> {
    let diff = cfg_into_iter!(vec_a)
        .zip(vec_b)
        .map(|(a, b)| (*a) - (*b))
        .collect();

    diff
}

fn had_product<F: Field>(vec_a: &Vec<F>, vec_b: &Vec<F>) -> Vec<F> {
    let had_prod = cfg_into_iter!(vec_a)
        .zip(vec_b)
        .map(|(a, b)| (*a) * (*b))
        .collect();

    had_prod
}

fn scalar_mult<F: Field>(c: &F, vec_a: &Vec<F>) -> Vec<F> {
    let result: Vec<F> = cfg_into_iter!(vec_a).map(|a| (*a) * (*c)).collect();
    result
}

#[cfg(test)]
pub mod test {
    use core::panic;
    use super::*;
    use ark_crypto_primitives::crh::{
        poseidon::{
            constraints::{CRHParametersVar, TwoToOneCRHGadget},
            TwoToOneCRH,
        },
        TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
    };
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_ed_on_bls12_381::Fr;
    use ark_ff::One;
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
    use r1cs_nark::{
        poseidon_parameters, R1CSNark
    };
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
            Ok(())
        }
    }

    #[test]
    pub fn test_null_accumulator() {
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
        let pp = R1CSNark::<Fr>::setup();

        let Ok((ipk, ivk)) = R1CSNark::<Fr>::index(&pp, hash_circ.clone()) else {
            panic!("prover key not generated")
        };

        let null_acc_instance = AccumulatorInstance::<Fr>::zero(ipk.clone());
        let null_acc_witness = AccumulatorWitness::<Fr>::zero(ipk.clone());

        let null_accumulator_succeeded = BDASAccumulationScheme::decide(
            &ivk, 
            (&null_acc_instance, &null_acc_witness)
        ).unwrap();

        assert_eq!(null_accumulator_succeeded, true);
    }

    #[test]
    pub fn test_folding_single_proof() {
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
        let pp = R1CSNark::<Fr>::setup();

        let Ok((ipk, ivk)) = R1CSNark::<Fr>::index(&pp, hash_circ.clone()) else {
            panic!("prover key not generated")
        };

        let null_acc_instance = AccumulatorInstance::<Fr>::zero(ipk.clone());
        let null_acc_witness = AccumulatorWitness::<Fr>::zero(ipk.clone());

        let mut rng = ark_std::test_rng();
        let Ok(proof) = R1CSNark::<Fr>::prove(&ipk, hash_circ, Some(&mut rng)) else {
            panic!["proof not generated"]
        };

        if !R1CSNark::<Fr>::verify(
            &ivk, 
            &proof.instance.input, 
            &proof
        ) {
            panic!["R1CS proof not verified"];
        }

        let Ok(((new_acc_instance, new_acc_witness), acc_proof)) = BDASAccumulationScheme::<Fr>::prove(
            &ipk,
            (&null_acc_instance, &null_acc_witness),
            (&proof.instance, &proof.witness)
        ) else {
            panic!["accumulation proof not generated"]
        };

        let verification_result = BDASAccumulationScheme::<Fr>::verify(
            &ivk, 
            &acc_proof,
            (&null_acc_instance, &null_acc_witness), 
            (&new_acc_instance, &new_acc_witness), 
            (&proof.instance, &proof.witness)
        ).unwrap();

        if !verification_result {
            panic!["not able to verify accumulated proof"];
        }

        let decider_succeeded = BDASAccumulationScheme::decide(
            &ivk, 
            (&new_acc_instance, &new_acc_witness)
        ).unwrap();

        assert_eq!(decider_succeeded, true);
    }
}