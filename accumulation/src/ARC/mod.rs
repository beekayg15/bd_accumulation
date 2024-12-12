use anyhow::Result;
use ark_crypto_primitives::prf::{Blake2s, Blake2sWithParameterBlock, PRF};
use ark_crypto_primitives::{merkle_tree::MerkleTree, sponge::Absorb};
use ark_ff::{BigInt, PrimeField};
use ark_ff::{BigInteger, BigInteger256};
use ark_poly::Polynomial;
use reed_solomon::RSCode;
use std::usize;
pub mod reed_solomon;
use crate::bd_as::r1cs_nark::{poseidon_parameters, MerkleHashConfig};
struct RSProver<'a, F: PrimeField> {
    code1: &'a RSCode<F>,
    code2: &'a RSCode<F>,
    s: u16, //out ofdomain parameter
    t: u16, // indomain parameter
}
struct RSProof<F: PrimeField> {
    cm_code1: F,
    cm_code2: F,
}
pub fn generate_random_linear_combinator<F>(code1: &[Vec<F>], code2: &[Vec<F>]) -> Result<F>
where
    F: PrimeField<BigInt = BigInteger256>,
{
    let seed: F = code1.iter().fold(F::zero(), |sum, val| sum + val[0]);
    let inp = code2.iter().fold(F::zero(), |sum, val| sum + val[0]);
    let seed = seed.into_bigint().to_bytes_le();
    let inp = inp.into_bigint().to_bytes_le();
    let mut seed_32: [u8; 32] = [0_u8; 32];
    seed_32.copy_from_slice(&seed[..seed.len().min(32)]);
    let mut inp_32: [u8; 32] = [0_u8; 32];
    inp_32.copy_from_slice(&inp[..inp.len().min(32)]);
    let r: [u8; 32] = Blake2s::evaluate(&seed_32, &inp_32)?;
    let mut r_bits: Vec<bool> = vec![];
    for i in 0..32 {
        let mut x = r[i].clone();
        for _ in 0..8 {
            r_bits.push(x % 2 != 0);
            x = x >> 1;
        }
    }
    let r: F = F::from_bigint(BigInteger256::from_bits_le(&r_bits)).unwrap();
    Ok(r)
}
pub fn get_random_out_domain<F: PrimeField<BigInt = BigInteger256>>(
    cm1: F,
    cm2: F,
    cm3: F,
    s: u32,
) -> Vec<F> {
    let salt = cm1.into_bigint().to_bytes_le();
    let mut salt_8: [u8; 8] = [0_u8; 8];
    salt_8.copy_from_slice(&salt[..salt.len().min(8)]);
    let pers = (cm2).into_bigint().to_bytes_le();
    let mut pers_8: [u8; 8] = [0_u8; 8];
    pers_8.copy_from_slice(&pers[..pers.len().min(8)]);
    let b2s_params = Blake2sWithParameterBlock {
        output_size: 8,
        key_size: 32,
        salt: salt_8,
        personalization: pers_8,
    };
    let mut r: Vec<F> = vec![];
    for i in 0..s as usize {
        let mut inp = cm3.into_bigint().to_bytes_le().to_vec();
        inp.extend(i.to_le_bytes());
        let val1: Vec<u8> = b2s_params.evaluate(&inp);
        let v1 = u64::from_le_bytes(val1[..8].try_into().unwrap());
        let val2: Vec<u8> = b2s_params.evaluate(&inp);
        let v2 = u64::from_le_bytes(val2[..8].try_into().unwrap());
        let val3: Vec<u8> = b2s_params.evaluate(&inp);
        let v3 = u64::from_le_bytes(val3[..8].try_into().unwrap());
        let val4: Vec<u8> = b2s_params.evaluate(&inp);
        let v4 = u64::from_le_bytes(val4[..8].try_into().unwrap());

        let mut f_bint = BigInteger256::from(0_u8);
        f_bint.0 = [v1, v2, v3, v4];
        r.push(F::from_bigint(f_bint).unwrap());
    }
    r
}
pub fn get_indices<F: PrimeField<BigInt = BigInteger256>>(
    cm1: F,
    cm2: F,
    cm3: F,
    s: u32,
    sz: usize,
) -> Vec<usize> {
    let salt = cm1.into_bigint().to_bytes_le();
    let mut salt_8: [u8; 8] = [0_u8; 8];
    salt_8.copy_from_slice(&salt[..salt.len().min(8)]);
    let pers = (cm2).into_bigint().to_bytes_le();
    let mut pers_8: [u8; 8] = [0_u8; 8];
    pers_8.copy_from_slice(&pers[..pers.len().min(8)]);
    let b2s_params = Blake2sWithParameterBlock {
        output_size: 8,
        key_size: 32,
        salt: salt_8,
        personalization: pers_8,
    };
    let mut r: Vec<usize> = vec![];
    for i in 0..s as usize {
        let mut inp = cm3.into_bigint().to_bytes_le().to_vec();
        inp.extend(i.to_le_bytes());
        let val = b2s_params.evaluate(&inp);

        let v = u64::from_le_bytes(val[..8].try_into().unwrap());
        r.push((v % sz as u64) as usize);
    }
    r
}
impl<F: PrimeField<BigInt = BigInteger256> + Absorb> RSProver<'_, F> {
    pub fn prove(self) -> Result<RSProof<F>> {
        let r = generate_random_linear_combinator(&self.code1.code, &self.code2.code)?;
        let merkle_tree_code1 = MerkleTree::<MerkleHashConfig<F>>::new(
            &poseidon_parameters(),
            &poseidon_parameters(),
            self.code1.code.to_vec(),
        )
        .unwrap();
        let merkle_tree_code2 = MerkleTree::<MerkleHashConfig<F>>::new(
            &poseidon_parameters(),
            &poseidon_parameters(),
            self.code2.code.to_vec(),
        )
        .unwrap();
        let mut random_linear_combination: Vec<F> = vec![];
        for ind in 0..self.code1.coeffs.len().max(self.code2.coeffs.len()) {
            if ind > self.code1.coeffs.len() {
                random_linear_combination.push(r * self.code2.coeffs[ind]);
            } else if ind > self.code2.coeffs.len() {
                random_linear_combination.push(self.code1.coeffs[ind]);
            } else {
                random_linear_combination
                    .push(self.code1.coeffs[ind] + (r * self.code2.coeffs[ind]));
            }
        }
        let rand_linear_code =
            RSCode::<F>::encode(random_linear_combination, self.code1.t.max(self.code2.t));
        let merkle_tree_combined = MerkleTree::<MerkleHashConfig<F>>::new(
            &poseidon_parameters(),
            &poseidon_parameters(),
            rand_linear_code.code,
        )
        .unwrap();
        let m1_tree_root: F = merkle_tree_code1.root();
        let m2_tree_root: F = merkle_tree_code2.root();
        let mcomb_tree_root: F = merkle_tree_combined.root();
        let sz = self.code1.code.len().max(self.code2.code.len());
        let out_domain_points: Vec<F> = get_random_out_domain(
            merkle_tree_code1.root(),
            merkle_tree_code2.root(),
            merkle_tree_combined.root(),
            self.s.into(),
        );
        let mut out_domain_evals: Vec<(F, F)> = vec![];
        for ind in out_domain_points.iter() {
            out_domain_evals.push((ind.clone(), rand_linear_code.poly.evaluate(&ind)));
        }

        let r_indices = get_indices(
            m1_tree_root,
            m2_tree_root,
            mcomb_tree_root,
            self.t.into(),
            sz,
        );
        todo!()
    }
}
