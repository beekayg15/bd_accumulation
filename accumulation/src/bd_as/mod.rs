pub mod r1cs_nark;

use crate::bd_as::r1cs_nark::MerkleHashConfig;
use crate::AccumulationScheme;
use ark_crypto_primitives::merkle_tree::{MerkleTree, Path};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::cfg_into_iter;
use ark_std::marker::PhantomData;
use r1cs_nark::{FullAssignment, CommitmentFullAssignment, IndexProverKey, IndexVerifierKey, matrix_vec_mul, poseidon_parameters};
use ark_relations::r1cs::SynthesisError;

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
    opening_random_location: Vec<Path<MerkleHashConfig<F>>>,
    blinded_t: F,
}
#[derive(Clone)]
struct BDASAccumulationScheme<F: PrimeField + Absorb> {
    _field_data: PhantomData<F>,
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
        input: (&'a Self::InputInstance, &'a Self::InputWitness) 
    ) -> Result<((&'a Self::AccumulatorInstance, &'a Self::AccumulatorWitness),&'a Self::Proof),SynthesisError> {
        
        // Using Fiat-Shamir to compute randomness of the linear combination 
        let r: F = None;

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
            &add_vectors(&cw, &scalar_mult(&r, &cz))
        );

        let t_modified: Vec<[F; 1]> = vec![];
        for &i in t.iter() {
            t_modified.push([i.clone()]);
        }

        let w_modified: Vec<[F; 1]> = vec![];
        for &i in acc_instance.w.iter() {
            w_modified.push([i.clone()]);
        }

        let z_modified: Vec<[F; 1]> = vec![];
        for &i in assignment.input.iter() {
            z_modified.push([i.clone()]);
        }
        for &i in assignment.witness.iter() {
            z_modified.push([i.clone()]);
        }

        let err_modified: Vec<[F; 1]> = vec![];
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
        MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, err_modified).unwrap();

        assert_eq!(err_tree.root(), acc_witness.blinded_err);
        assert_eq!(w_tree.root(), acc_witness.blinded_w);
        assert_eq!(z_tree.root(), commitment.blinded_assignment);

        let blinded_t = t_tree.root();

        let new_w = add_vectors(
            &acc_instance.w, 
            &scalar_mult(&r, &acc_instance.w)
        );

        let new_err = add_vectors(
            &acc_instance.err,
            &scalar_mult(&r, &t)
        );

        let new_acc_instance = AccumulatorInstance {
            w: new_w,
            err: new_err,
            c: acc_instance.c + r,
        };

        let new_err_modified: Vec<[F; 1]> = vec![];
        for &i in new_err.iter() {
            new_err_modified.push([i.clone()]);
        }

        let new_w_modified: Vec<[F; 1]> = vec![];
        for &i in new_w.iter() {
            new_w_modified.push([i.clone()]);
        }

        let new_w_tree =   
        MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, new_w_modified).unwrap();

        let new_err_tree =   
        MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, new_err_modified).unwrap();

        let new_acc_witness = AccumulatorWitness {
            blinded_err: new_err_tree.root(),
            blinded_w: new_w_tree.root(),
        };

        let proof = Proof {
            opening_random_location: vec![],
            blinded_t: blinded_t,
        };

        Ok(((&new_acc_instance, &new_acc_witness), &proof))
    }

    fn verify<'a>(
        verifier_key: &'a Self::VerifierKey,
        proof: &Self::Proof, 
        accumulated_proofs: (&'a Self::AccumulatorInstance,&'a Self::AccumulatorWitness)
    ) -> Result<bool,SynthesisError> {
        Ok(false)
    }

    fn decide<'a> (
        decider_key: &'a Self::DeciderKey,
        accumulator: (&'a Self::AccumulatorInstance,&'a Self::AccumulatorWitness) 
    ) -> Result<bool,SynthesisError> {
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
        MerkleTree::<MerkleHashConfig<F>>::new(&hash_params, &hash_params, err_modified).unwrap();

        assert_eq!(w_tree.root(), witness.blinded_w);
        assert_eq!(err_tree.root(), witness.blinded_err);

        let lhs = had_product(&aw, &bw);
        let rhs = add_vectors(
            &instance.err, 
            &scalar_mult(&instance.c, &cw)
        );

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
    let result = cfg_into_iter!(vec_a)
        .map(|a| (*a) * (*c))
        .collect();
    result
}