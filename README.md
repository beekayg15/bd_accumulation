# Accumulation without Homomorphism using Arkworks

This is the implementation of the accumulation scheme without using quantum-vulnerable homomorphic commitment schemes, as described in <a href="https://eprint.iacr.org/2024/474">"Accumulation without Homorphism"</a> by Benedikt Bunz, Pratyush Mishra, Wilson Nguyen, and Wiliam Wang.

## Overview

Accumulation schemes are primarily used in incrementally verifiable computations(IVCs) to prove that a series of computations have been computed correctly. Accumulation schemes provide a way to fold recursive proofs together into an accumulator in a manner that inorder to prove that the individuals proofs were valid, it is sufficient to prove that the final accumulator is valid. Thus eliminates the overhead of verifying the proof of previous computation in each step and is replaced by a single slightly expensive verification step at the end of the computation. Thereby, making IVCs and PCDs more efficient. Also, the size of the accumulator is independent of the number of step of comuputation, which is an additional advantage. The variants introduced in [Nova](https://eprint.iacr.org/2024/232.pdf) and [ProtoStar](https://eprint.iacr.org/2023/620) provide accumulation schemes that are efficient but have the drawback of using homomorphic commitment schemes as a vital components in their constructions, which are proven not to be quantum secure. 

The implementation provided here, overcomes the issue by replacing the homomorphism check with a two process: *linear encodings* and *merkle-tree spot checking*.
