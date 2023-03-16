#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unreachable_code)]

//! A circuit is a layout of columns over multiple rows, capable of building or
//! defining their own custom constraints. In the [`zkEVM`] architecture, many
//! such circuits (individually termed as sub-circuits) are placed within a
//! super-circuit. When a circuit encounters an expensive operation, it can
//! outsource the verification effort to another circuit through the usage of
//! lookup arguments.
//!
//! For instance, the [`EVM-circuit`] would like to verify the output of a call
//! to the precompiled contract [`SHA2-256`], which in itself is an expensive
//! operation to verify. So in order to separate out the verification logic and
//! build a more developer-friendly approach, the EVM circuit would use the
//! SHA2-256 circuit's table via lookups to communicate simply the input-output
//! relationship, outsourcing the effort of verifying the relationship itself
//! to the SHA2-256 circuit.
//!
//! In the sha2-256-circuit crate, we export the SHA2-256 circuit's config `Sha2Config`,
//! and the table within it (that other circuits can use as a lookup argument)
//! `Sha2Table`. The config type defines the layout of the circuit, the various
//! named columns in the circuit's layout, and the `configure` method is meant
//! to define the relationship between those columns over its neighbouring rows.
//!
//! For instance, for the `id` field to be an incremental field, one may specify
//! the following relationship:
//! ```
//! # impl<F: FieldExt> Sha2Config<F> {
//!     pub fn configure(meta: &mut ConstraintSystem<F>, table: Sha2Table) -> Self {
//!         meta.create_gate("validity check over all rows", |meta| {
//!             let mut cb = BaseConstraintBuilder::default();
//!             cb.require_equal(
//!                 "id field is incremental, i.e. id::cur + 1 == id::next",
//!                 meta.query_advice(table.id, Rotation::cur()) + 1.expr(),
//!                 meta.query_advice(table.id, Rotation::next()),
//!             );
//!             cb.gate(1.expr()) // enable this gate over all rows.
//!         });
//!
//!         Self {
//!             table,
//!             _marker: PhantomData,
//!         }
//!     }
//! # }
//! ```
//!
//! We also describe how the EVM circuit would lookup to the SHA2 circuit via lookup
//! arguments [`here`]. Currently, the table is a dummy column named `id`.
//!
//! The following tasks are expected to be done:
//! - Define the layout of the SHA2-256 circuit through columns in `Sha2Config`.
//! - Define the lookup argument exposed by SHA2-256 circuit via `Sha2Table`.
//! - Define verification logic over rows of the circuit by constraining the relationship
//!   between the columns.
//! - Assign witness data to the circuit via the `load` method.
//! - Test the verification logic in the circuit.
//!
//! [`zkEVM`]: https://privacy-scaling-explorations.github.io/zkevm-docs/introduction.html
//! [`EVM-circuit`]: https://github.com/scroll-tech/zkevm-circuits/blob/scroll-stable/zkevm-circuits/src/evm_circuit.rs
//! [`SHA2-256`]: https://en.wikipedia.org/wiki/SHA-2#Pseudocode
//! [`here`]: https://github.com/scroll-tech/zkevm-circuits/pull/398

use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{Advice, Any, Column, ConstraintSystem, Error},
};

#[derive(Clone, Debug)]
pub struct Sha2Table {
    id: Column<Advice>,
}

impl Sha2Table {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            id: meta.advice_column(),
        }
    }

    pub fn columns(&self) -> Vec<Column<Any>> {
        vec![self.id.into()]
    }

    pub fn annotations(&self) -> Vec<String> {
        vec![String::from("id")]
    }
}

#[derive(Clone, Debug)]
pub struct Sha2Config<F> {
    table: Sha2Table,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Sha2Config<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, table: Sha2Table) -> Self {
        Self {
            table,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Sha2Witness<F> {
    pub inputs: Vec<Vec<u8>>,
    pub _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct Sha2Chip<F> {
    config: Sha2Config<F>,
    data: Sha2Witness<F>,
}

impl<F: FieldExt> Sha2Chip<F> {
    pub fn construct(config: Sha2Config<F>, data: Sha2Witness<F>) -> Self {
        Self { data, config }
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(any(feature = "test", test))]
pub mod dev {
    use super::*;

    use ethers_core::types::H256;
    use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};
    use std::str::FromStr;

    lazy_static::lazy_static! {
        pub static ref INPUTS_OUTPUTS: (Vec<Vec<u8>>, Vec<H256>) = {
        [
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            ),
        ]
            .iter()
            .map(|(input, output)| {
                (
                    input.as_bytes().to_vec(),
                    H256::from_str(output).expect("SHA-256 hash is 32-bytes"),
                )
            })
            .unzip()
        };
    }

    #[derive(Default)]
    pub struct Sha2TestCircuit<F> {
        pub inputs: Vec<Vec<u8>>,
        pub outputs: Vec<H256>,
        pub _marker: PhantomData<F>,
    }

    impl<F: FieldExt> Circuit<F> for Sha2TestCircuit<F> {
        type Config = Sha2Config<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let sha2_table = Sha2Table::construct(meta);
            Sha2Config::configure(meta, sha2_table)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let chip = Sha2Chip::construct(
                config,
                Sha2Witness {
                    inputs: self.inputs.clone(),
                    _marker: PhantomData,
                },
            );
            chip.load(&mut layouter)
        }
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use std::marker::PhantomData;

    use crate::dev::{Sha2TestCircuit, INPUTS_OUTPUTS};

    #[test]
    fn test_sha2_circuit() {
        let (inputs, outputs) = INPUTS_OUTPUTS.clone();

        let circuit: Sha2TestCircuit<Fr> = Sha2TestCircuit {
            inputs,
            outputs,
            _marker: PhantomData,
        };

        let k = 8;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
