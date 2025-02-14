use ark_ff::PrimeField;
use ark_poly::{
    polynomial::DenseUVPolynomial,
    univariate::DensePolynomial,
    Polynomial,
};
#[derive(Clone)]
pub struct RSCode<F: PrimeField> {
    pub evaluation_domain: Vec<F>,
    pub code: Vec<F>,
    pub coeffs: Vec<F>,
    pub poly: DensePolynomial<F>,
    pub t: u64,
    pub d: u64,
}

impl<F: PrimeField> RSCode<F> {
    pub fn encode(coeff: Vec<F>, t: u64) -> Self {
        let poly: DensePolynomial<F> = DensePolynomial::<F>::from_coefficients_vec(coeff.clone());
        let mut evaluation_domain: Vec<F> = vec![];
        let mut field_prim = F::GENERATOR;
        let d: u64 = coeff.len() as u64;
        let mut evals: Vec<F> = vec![];
        for _pow in 1..(t+1) {
            evals.push(poly.evaluate(&field_prim));
            evaluation_domain.push(field_prim.clone());
            field_prim *= F::GENERATOR;
        }
        RSCode {
            evaluation_domain,
            code: evals,
            coeffs: coeff,
            poly,
            t,
            d,
        }
    }
}