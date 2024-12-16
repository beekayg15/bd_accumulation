use std::error::Error;

use anyhow::{Error, R)esult};
use ark_ff::PrimeField;
use ark_poly::{
    polynomial::DenseUVPolynomial,
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
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
        for _pow in 1..t {
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

    pub fn get_commit_vector(self) -> Vec<[F; 2]> {
        let mut v: Vec<[F; 2]> = vec![];
        for (x, y) in self.evaluation_domain.iter().zip(self.code.iter()) {
            v.push([x.clone(), y.clone()]);
        }
        return v;
    }
    pub fn vanishing_poly(self, s: Vec<F>) -> DensePolynomial<F> {
        let mut vanishing_poly_s = DensePolynomial::<F>::from_coefficients_vec(vec![F::one()]);
        for x in s.iter() {
            let poly_x_root: DensePolynomial<F> =
                DensePolynomial::<F>::from_coefficients_vec(vec![F::zero() - x, F::one()]);
            vanishing_poly_s = vanishing_poly_s.naive_mul(&poly_x_root);
        }
        vanishing_poly_s
    }
    pub fn get_lagrange_interpolation(self, evals: Vec<(F, F)>) -> DensePolynomial<F> {
        let s: Vec<F> = evals.iter().map(|(v1, _)| v1.clone()).collect();
        let vanishing_poly_s = self.vanishing_poly(s);

        let mut lagrange_poly: DensePolynomial<F> =
            DensePolynomial::from_coefficients_vec(vec![F::zero()]);
        for (x, y) in evals.iter() {
            if let Some((lpq, _lpr)) = DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&vanishing_poly_s.clone()).into(),
                &(&DensePolynomial::<F>::from_coefficients_vec(vec![F::zero() - x, F::one()]))
                    .into(),
            ) {
                let val = *y / lpq.evaluate(x);
                let lpa = DensePolynomial::<F>::from_coefficients_vec(vec![val]);
                let lpa = lpa.naive_mul(&lpq);
                lagrange_poly = lagrange_poly + lpa;
            };
        }
        lagrange_poly
    }
    pub fn poly_quotient(self, s: Vec<F>) -> Result<Vec<(F, F)>> {
        let mut r: Vec<(F, F)> = vec![];
        for i in s.iter() {
            r.push((i.clone(), self.poly.clone().evaluate(i)));
        }
        let interpolated_f: DensePolynomial<F> = self.clone().get_lagrange_interpolation(r);
        println!("interpolated coeffs{:?}", interpolated_f.coeffs);
        let dividend: DensePolynomial<F> = &self.poly.clone() - &interpolated_f;
        let divisor = self.vanishing_poly(s.clone());
        if let Some((quotient, _rem)) =
            DenseOrSparsePolynomial::divide_with_q_and_r(&(&dividend).into(), &(&divisor).into())
        {
            println!("rem coeffs:{:?}", _rem.coeffs);
            let mut evals: Vec<(F, F)> = vec![];
            for x in s.iter() {
                evals.push((x.clone(), quotient.evaluate(x)));
            }
            Ok(evals)
        } else {
            Err("Err")
        }
    }
}

#[cfg(test)]
mod rs_test {
    use super::*;
    use ark_ed_on_bls12_381::Fr;
    use ark_ff::{FftField, Field};
    #[test]
    pub fn test_vanish() {
        let words: Vec<Fr> = vec![
            <Fr as Field>::ONE,
            <Fr as FftField>::GENERATOR,
            <Fr as Field>::ONE,
            <Fr as Field>::ONE + <Fr as FftField>::GENERATOR,
            <Fr as FftField>::GENERATOR + <Fr as FftField>::GENERATOR,
            <Fr as FftField>::GENERATOR * <Fr as FftField>::GENERATOR,
        ];
        let rs: RSCode<Fr> = RSCode::encode(words, 9);
        println!("code: {:?}", rs.code);
        println!("eval domain: {:?}", rs.evaluation_domain);
        let s: Vec<Fr> = vec![
            <Fr as Field>::ONE + <Fr as Field>::ONE,
            <Fr as Field>::ONE + <Fr as Field>::ONE + <Fr as Field>::ONE + <Fr as Field>::ONE,
            <Fr as Field>::ONE + <Fr as Field>::ONE + <Fr as Field>::ONE,
        ];
        if let Some(poly_q) = rs.poly_quotient(s) {
            println!("{:?}", poly_q,)
        }
    }
}
