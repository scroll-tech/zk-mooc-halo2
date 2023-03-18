# zk-mooc-halo2

This repository provides skeleton code to build circuits for the "Category 4: Circuit Development in Halo2-ce"
track under https://zk-hacking.org.

The repository consists of 3 member crates, specifically `blake2f-circuit`, `ripemd160-circuit` and `sha2-256-circuit`,
to configure constraints for verifying the input-output relationships for each of the hash functions. These hash
functions are [precompiled contracts](https://www.evm.codes/precompiled) in the Ethereum Virtual Machine, and Scroll's
zkEVM architecture relies on these circuits and their tables to check the input-output relationship via lookup arguments.

The repository also contains a `benchmarking` crate to benchmark and further optimise the layout of each of the circuits.
To run the benchmarks and see the output run the following commands:
```
cd benchmarking
DEGREE=10 cargo test -- --nocapture
```
