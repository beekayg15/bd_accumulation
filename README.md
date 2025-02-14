# Accumulation without Homomorphism using Arkworks

This is the implementation of the accumulation scheme without using quantum-vulnerable homomorphic commitment schemes, as described in <a href="https://eprint.iacr.org/2024/474">"Accumulation without Homorphism"</a> by Benedikt Bunz, Pratyush Mishra, Wilson Nguyen, and Wiliam Wang.

## Overview

Accumulation schemes are primarily used in incrementally verifiable computations(IVCs) to prove that a series of computations have been computed correctly. Accumulation schemes provide a way to fold recursive proofs together into an accumulator in a manner that inorder to prove that the individuals proofs were valid, it is sufficient to prove that the final accumulator is valid. Thus eliminates the overhead of verifying the proof of previous computation in each step and is replaced by a single slightly expensive verification step at the end of the computation. Thereby, making IVCs and PCDs more efficient. Also, the size of the accumulator is independent of the number of step of comuputation, which is an additional advantage. The variants introduced in [Nova](https://eprint.iacr.org/2024/232.pdf) and [ProtoStar](https://eprint.iacr.org/2023/620) provide accumulation schemes that are efficient but have the drawback of using homomorphic commitment schemes as a vital components in their constructions, which are proven not to be quantum secure. 

The implementation provided here, overcomes the issue by replacing the homomorphism check with a two process: *linear encodings* and *merkle-tree spot checking*.

## License

MIT License

Copyright (c) 2025 Barath Kumar GaneshKumar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Citation

This is an implementation of the Accumulation without Homomorphism protocol described in the following paper. If you use this implementation, please cite both this repository and the original paper:

The original paper:

```bibtex
@misc{cryptoeprint:2024/474,
      author = {Benedikt Bünz and Pratyush Mishra and Wilson Nguyen and William Wang},
      title = {Accumulation without Homomorphism},
      howpublished = {Cryptology {ePrint} Archive, Paper 2024/474},
      year = {2024},
      url = {https://eprint.iacr.org/2024/474}
}
```

This implementation:

```bibtex
@software{rust_kvac_impl,
    author = {Barath GaneshKumar},
    title = {Rust Implementation of Accumulation without Homomorphism},
    year = {2025},
    url = {github.com/beekayg15/bd_accumulation},
    note = {Implementation of Accumulation without Homomorphism by Bünz, Mishra, Nguyen, and Wang}
}
```

## References

- Original Paper: [Accumulation without Homomorphism](https://eprint.iacr.org/2024/474)
- This implementation is based on the algorithms and protocols described in the paper above
