#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unreachable_code)]

use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{Advice, Any, Column, ConstraintSystem, Error},
};

#[derive(Clone, Debug)]
pub struct Ripemd160Table {
    id: Column<Advice>,
}

impl Ripemd160Table {
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
pub struct Ripemd160Config<F> {
    table: Ripemd160Table,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Ripemd160Config<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, table: Ripemd160Table) -> Self {
        Self {
            table,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ripemd160Witness<F> {
    pub inputs: Vec<Vec<u8>>,
    pub _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct Ripemd160Chip<F> {
    config: Ripemd160Config<F>,
    data: Ripemd160Witness<F>,
}

impl<F: FieldExt> Ripemd160Chip<F> {
    pub fn construct(config: Ripemd160Config<F>, data: Ripemd160Witness<F>) -> Self {
        Self { config, data }
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(any(feature = "test", test))]
pub mod dev {
    use super::*;

    use ethers_core::types::H160;
    use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};
    use std::str::FromStr;

    lazy_static::lazy_static! {
        pub static ref INPUTS_OUTPUTS: (Vec<Vec<u8>>, Vec<H160>) = {
            [
                ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
                ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
                (
                    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                    "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
                ),
                (
                    "abcdefghijklmnopqrstuvwxyz",
                    "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
                ),
            ]
            .iter()
            .map(|(input, output)| {
                (
                    input.as_bytes().to_vec(),
                    H160::from_str(output).expect("ripemd-160 hash is 20-bytes"),
                )
            })
            .unzip()
        };
    }

    #[derive(Default)]
    pub struct Ripemd160TestCircuit<F> {
        pub inputs: Vec<Vec<u8>>,
        pub outputs: Vec<H160>,
        pub _marker: PhantomData<F>,
    }

    impl<F: FieldExt> Circuit<F> for Ripemd160TestCircuit<F> {
        type Config = Ripemd160Config<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let ripemd160_table = Ripemd160Table::construct(meta);
            Ripemd160Config::configure(meta, ripemd160_table)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let chip = Ripemd160Chip::construct(
                config,
                Ripemd160Witness {
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

    use crate::dev::{Ripemd160TestCircuit, INPUTS_OUTPUTS};

    #[test]
    fn test_ripemd160_circuit() {
        let (inputs, outputs) = INPUTS_OUTPUTS.clone();

        let circuit: Ripemd160TestCircuit<Fr> = Ripemd160TestCircuit {
            inputs,
            outputs,
            _marker: PhantomData,
        };

        let k = 8;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
