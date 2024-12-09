pub mod r1cs_nark;

use crate::bd_as::r1cs_nark::MerkleHashConfig;
use crate::AccumulationScheme;
use ark_crypto_primitives::merkle_tree::{MerkleTree, Path};
use ark_crypto_primitives::prf::blake2s::Blake2s;
use ark_crypto_primitives::prf::PRF;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::cfg_into_iter;
use ark_std::marker::PhantomData;
use r1cs_nark::{
    matrix_vec_mul, poseidon_parameters, CommitmentFullAssignment, FullAssignment, IndexProverKey,
    IndexVerifierKey,
};

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
struct AccumulatorInstance<F: PrimeField> {
    w: Vec<F>,
    err: Vec<F>,
    c: F,
}
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
struct AccumulatorWitness<F: PrimeField + Absorb> {
    blinded_w: F, //this is the root of a merkle tree for posiedon inner digest defined in
    //MerkleHashConfig
    blinded_err: F,
}

#[derive(Clone)]
struct Proof<F: PrimeField + Absorb> {
    acc_openings: Vec<Path<MerkleHashConfig<F>>>,
    new_acc_openings: Vec<Path<MerkleHashConfig<F>>>,
    input_openings: Vec<Path<MerkleHashConfig<F>>>,
    err_openings: Vec<Path<MerkleHashConfig<F>>>,
    new_err_openings: Vec<Path<MerkleHashConfig<F>>>,
    t_openings: Vec<Path<MerkleHashConfig<F>>>,
    blinded_t: F,
    t: Vec<F>,
}
#[derive(Clone)]
struct BDASAccumulationScheme<F: PrimeField + Absorb> {
    _field_data: PhantomData<F>,
}
fn bytes_to_field_vec<F: PrimeField>(bytes: [u8; 32]) -> Vec<F> {
    let bits_per_elem = F::MODULUS_BIT_SIZE as usize;
    let bytes_per_elem = (bits_per_elem + 7) / 8; // Convert bits to bytes, rounding up
    let mut result = Vec::new();

    // Iterate over chunks of the byte array and convert each chunk to a field element
    for chunk in bytes.chunks(bytes_per_elem) {
        // Convert the byte array to a BigInteger and then to a field element
        if let Some(elem) = F::from_random_bytes(chunk) {
            result.push(elem);
        }
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

        let (assignment, commitment) = input;
        let num_input_variables = assignment.input.len();
        let num_witness_variables = assignment.witness.len();
        let num_variables = num_witness_variables + num_input_variables;

        assert_eq!(prover_key.index_info.num_variables, num_variables);

        let (acc_instance, acc_witness) = old_accumulator;
        let num_acc_variables = acc_instance.w.len();

        assert_eq!(prover_key.index_info.num_variables, num_acc_variables);
        assert_eq!(prover_key.index_info.num_variables, acc_instance.err.len());

        let az = matrix_vec_mul(&prover_key.a, &assignment.input, &assignment.witness);
        let bz = matrix_vec_mul(&prover_key.b, &assignment.input, &assignment.witness);
        let cz = matrix_vec_mul(&prover_key.c, &assignment.input, &assignment.witness);

        let aw = matrix_vec_mul(&prover_key.a, &acc_instance.w, &[]);
        let bw = matrix_vec_mul(&prover_key.b, &acc_instance.w, &[]);
        let cw = matrix_vec_mul(&prover_key.c, &acc_instance.w, &[]);

        let azbw = had_product(&az, &bw);
        let awbz = had_product(&aw, &bz);

        let t = sub_vectors(
            &add_vectors(&azbw, &awbz),
            &add_vectors(&cw, &scalar_mult(&r, &cz)),
        );

        let mut t_modified: Vec<[F; 1]> = vec![];
        for &i in t.iter() {
            t_modified.push([i.clone()]);
        }

        let mut w_modified: Vec<[F; 1]> = vec![];
        for &i in acc_instance.w.iter() {
            w_modified.push([i.clone()]);
        }

        let mut z_modified: Vec<[F; 1]> = vec![];
        for &i in assignment.input.iter() {
            z_modified.push([i.clone()]);
        }
        for &i in assignment.witness.iter() {
            z_modified.push([i.clone()]);
        }

        let mut err_modified: Vec<[F; 1]> = vec![];
        for &i in acc_instance.err.iter() {
            err_modified.push([i.clone()]);
        }

        let hash_params = poseidon_parameters::<F>();

        let t_tree =
            MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, t_modified).unwrap();

        let w_tree =
            MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, w_modified).unwrap();

        let z_tree =
            MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, z_modified).unwrap();

        let err_tree =
            MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, err_modified)
                .unwrap();

        assert_eq!(err_tree.root(), acc_witness.blinded_err);
        assert_eq!(w_tree.root(), acc_witness.blinded_w);
        assert_eq!(z_tree.root(), commitment.blinded_assignment);

        let blinded_t = t_tree.root();

        let new_w = add_vectors(&acc_instance.w, &scalar_mult(&r, &acc_instance.w));

        let new_err = add_vectors(&acc_instance.err, &scalar_mult(&r, &t));

        let new_acc_instance = AccumulatorInstance {
            w: new_w.clone(),
            err: new_err.clone(),
            c: acc_instance.c + r,
        };

        let mut new_err_modified: Vec<[F; 1]> = vec![];
        for &i in new_err.iter() {
            new_err_modified.push([i]);
        }

        let mut new_w_modified: Vec<[F; 1]> = vec![];
        for &i in new_w.iter() {
            new_w_modified.push([i.clone()]);
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
            num_variables
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

        for opening in input_openings {
            if !opening.verify(
                &hash_params,
                &hash_params,
                &input_witness.blinded_assignment,
                [input_assignment[counter]],
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
                [acc_instance.w[counter]],
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
                [new_acc_instance.w[counter]],
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
                [t[counter]]
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
                [acc_instance.err[counter]],
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
                [new_acc_instance.err[counter]],
            ).unwrap() {
                return Ok(false);
            }
            counter += 1;
        }

        let r: F = get_randomness(
            vec![input.1.blinded_assignment],
            vec![old_accumulator.1.blinded_w],
        )[0];

        let opening_indexes = get_random_indices(
            16,
            vec![input.1.blinded_assignment],
            vec![old_accumulator.1.blinded_w],
            verifier_key.index_info.num_variables
        );

        if acc_instance.c + r != new_acc_instance.c {
            return Ok(false);
        }

        let mut counter = 0;

        for i in opening_indexes {
            if i != acc_openings[counter].leaf_index {
                return Ok(false);
            }

            if i != new_acc_openings[counter].leaf_index {
                return Ok(false);
            }

            if i != input_openings[counter].leaf_index {
                return Ok(false);
            }

            if new_acc_instance.w[i] != acc_instance.w[i] + r * input_assignment[i] {
                return Ok(false);
            }


            if i != new_err_openings[counter].leaf_index {
                return Ok(false);
            }

            if i != err_openings[counter].leaf_index {
                return Ok(false);
            }

            if i != t_openings[counter].leaf_index {
                return Ok(false);
            }

            if new_acc_instance.err[i] != acc_instance.err[i] + r * t[i] {
                return Ok(false);
            }

            counter += 1;
        }

        Ok(true)
    }

    fn decide<'a>(
        decider_key: &'a Self::DeciderKey,
        accumulator: (&'a Self::AccumulatorInstance, &'a Self::AccumulatorWitness),
    ) -> Result<bool, SynthesisError> {
        let (instance, witness) = accumulator;

        let aw = matrix_vec_mul(&decider_key.a, &instance.w, &[]);
        let bw = matrix_vec_mul(&decider_key.b, &instance.w, &[]);
        let cw = matrix_vec_mul(&decider_key.c, &instance.w, &[]);

        let mut w_modified: Vec<[F; 1]> = vec![];
        for i in instance.w.iter() {
            w_modified.push([i.clone()]);
        }

        let mut err_modified: Vec<[F; 1]> = vec![];
        for i in instance.err.iter() {
            err_modified.push([i.clone()]);
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

        Ok(lhs == rhs)
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
    let result = cfg_into_iter!(vec_a).map(|a| (*a) * (*c)).collect();
    result
}

#[cfg(test)]
pub mod test {
    
}