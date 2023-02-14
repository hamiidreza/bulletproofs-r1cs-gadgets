extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;

use bulletproofs::r1cs::{ConstraintSystem, R1CSError, R1CSProof, Variable, Prover, Verifier};
use curve25519_dalek::scalar::Scalar;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use bulletproofs::r1cs::LinearCombination;
use std::cmp;
use std::time::Instant;
use rand::rngs::OsRng;
use rand::Rng;
use crate::r1cs_utils::{AllocatedQuantity, positive_no_gadget, constrain_lc_with_scalar};
use merlin::Transcript;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_r1cs_range_proof() {
        test_range_proof_gadget();
        test_range_proof_and_gadget();    
    }

    fn test_range_proof_gadget() {
        let n: u8 = 64;
        let v: u64 = 4294967295;
        println!(
            "A range proof statement \"{} < 2^{}\"",
            v, n
        );
        assert!(range_proof_helper(v, n).is_ok());
    }

    fn test_range_proof_and_gadget() {
        let n1: u8 = 64;
        let n2: u8 = 64;
        let v1: u64 = 4294967295;
        let v2: u64 = 1111111111;
        println!(
            "AND composition of two range proof statements: \"{} < 2^{} AND {} < 2^{}\"",
            v1, n1, v2, n2
        );
        assert!(range_proof_and_helper(v1, v2, n1, n2).is_ok());
    }

    fn range_proof_helper(v: u64, n: u8) -> Result<(), R1CSError> {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let start = Instant::now();
        let (proof, committed_value) = {

            // Prover makes a `ConstraintSystem` instance representing a range proof gadget
            let mut prover_transcript = Transcript::new(b"BoundsTest");
            let mut rng = rand::thread_rng();

            let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

            // Constrain v in [0, 2^n)
            let (committed_value, var_v) = prover.commit(v.into(), Scalar::random(&mut rng));
            let quantity_v = AllocatedQuantity {
                variable: var_v,
                assignment: Some(v),
            };
            assert!(positive_no_gadget(&mut prover, quantity_v, n.into()).is_ok());

            let proof = prover.prove(&bp_gens)?;

            (proof, committed_value)
        };
        println!(
            "\t proving time: {} ms",
            start.elapsed().as_millis() as u128
        );
        //println!("Proving done");

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let start = Instant::now();
        let mut verifier_transcript = Transcript::new(b"BoundsTest");
        let mut verifier = Verifier::new(&mut verifier_transcript);

        let var_v = verifier.commit(committed_value);
        let quantity_v = AllocatedQuantity {
            variable: var_v,
            assignment: None,
        };
        assert!(positive_no_gadget(&mut verifier, quantity_v, n.into()).is_ok());

        // Verifier verifies proof
        let proof_res = verifier.verify(&proof, &pc_gens, &bp_gens);
        println!(
            "\t verification time: {} ms",
            start.elapsed().as_millis() as u128
        );
        Ok(proof_res?)
    }


    fn range_proof_and_helper(v1: u64, v2: u64, n1: u8, n2: u8) -> Result<(), R1CSError> {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let start = Instant::now();
        let (proof, commitments) = {
            let mut comms = vec![];

            // Prover makes a `ConstraintSystem` instance representing a range proof gadget
            let mut prover_transcript = Transcript::new(b"BoundsTest");
            let mut rng = rand::thread_rng();

            let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

            // Constrain v1 in [0, 2^n1)
            let (com_v1, var_v1) = prover.commit(v1.into(), Scalar::random(&mut rng));
            let quantity_v1 = AllocatedQuantity {
                variable: var_v1,
                assignment: Some(v1),
            };
            assert!(positive_no_gadget(&mut prover, quantity_v1, n1.into()).is_ok());
            comms.push(com_v1);

            // Constrain v2 in [0, 2^n2)
            let (com_v2, var_v2) = prover.commit(v2.into(), Scalar::random(&mut rng));
            let quantity_v2 = AllocatedQuantity {
                variable: var_v2,
                assignment: Some(v2),
            };
            assert!(positive_no_gadget(&mut prover, quantity_v2, n2.into()).is_ok());
            comms.push(com_v2);

            let proof = prover.prove(&bp_gens)?;

            (proof, comms)
        };
        println!(
            "\t proving time: {} ms",
            start.elapsed().as_millis() as u128
        );
        //println!("Proving done");

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let start = Instant::now();
        let mut verifier_transcript = Transcript::new(b"BoundsTest");
        let mut verifier = Verifier::new(&mut verifier_transcript);

        let var_v1 = verifier.commit(commitments[0]);
        let quantity_v1 = AllocatedQuantity {
            variable: var_v1,
            assignment: None,
        };
        assert!(positive_no_gadget(&mut verifier, quantity_v1, n1.into()).is_ok());

        let var_v2 = verifier.commit(commitments[1]);
        let quantity_v2 = AllocatedQuantity {
            variable: var_v2,
            assignment: None,
        };
        assert!(positive_no_gadget(&mut verifier, quantity_v2, n2.into()).is_ok());

        // Verifier verifies proof
        let proof_res = verifier.verify(&proof, &pc_gens, &bp_gens);
        println!(
            "\t verification time: {} ms",
            start.elapsed().as_millis() as u128
        );
        Ok(proof_res?)
    }
}