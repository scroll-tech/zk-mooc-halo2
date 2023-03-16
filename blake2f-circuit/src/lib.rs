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
pub struct Blake2fTable {
    id: Column<Advice>,
}

impl Blake2fTable {
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
pub struct Blake2fConfig<F> {
    table: Blake2fTable,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Blake2fConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, table: Blake2fTable) -> Self {
        Self {
            table,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Blake2fWitness {
    pub rounds: u32,
    pub h: [u64; 8],
    pub m: [u64; 16],
    pub t: [u64; 2],
    pub f: bool,
}

#[derive(Clone, Debug)]
pub struct Blake2fChip<F> {
    config: Blake2fConfig<F>,
    data: Vec<Blake2fWitness>,
}

impl<F: FieldExt> Blake2fChip<F> {
    pub fn construct(config: Blake2fConfig<F>, data: Vec<Blake2fWitness>) -> Self {
        Self { config, data }
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(any(feature = "test", test))]
pub mod dev {
    use super::*;

    use ethers_core::{types::H512, utils::hex::FromHex};
    use halo2_proofs::{arithmetic::FieldExt, circuit::SimpleFloorPlanner, plonk::Circuit};
    use std::{marker::PhantomData, str::FromStr};

    lazy_static::lazy_static! {
        // https://eips.ethereum.org/EIPS/eip-152#example-usage-in-solidity
        pub static ref INPUTS_OUTPUTS: (Vec<Blake2fWitness>, Vec<H512>) = {
            let (h1, h2) = (
                <[u8; 32]>::from_hex("48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5").expect(""),
                <[u8; 32]>::from_hex("d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b").expect(""),
            );
            let (m1, m2, m3, m4) = (
                <[u8; 32]>::from_hex("6162630000000000000000000000000000000000000000000000000000000000").expect(""),
                <[u8; 32]>::from_hex("0000000000000000000000000000000000000000000000000000000000000000").expect(""),
                <[u8; 32]>::from_hex("0000000000000000000000000000000000000000000000000000000000000000").expect(""),
                <[u8; 32]>::from_hex("0000000000000000000000000000000000000000000000000000000000000000").expect(""),
            );
            (
                vec![
                    Blake2fWitness {
                        rounds: 12,
                        h: [
                            u64::from_le_bytes(h1[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(h1[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(h1[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(h1[0x18..0x20].try_into().expect("")),
                            u64::from_le_bytes(h2[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(h2[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(h2[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(h2[0x18..0x20].try_into().expect("")),
                        ],
                        m: [
                            u64::from_le_bytes(m1[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(m1[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(m1[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(m1[0x18..0x20].try_into().expect("")),
                            u64::from_le_bytes(m2[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(m2[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(m2[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(m2[0x18..0x20].try_into().expect("")),
                            u64::from_le_bytes(m3[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(m3[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(m3[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(m3[0x18..0x20].try_into().expect("")),
                            u64::from_le_bytes(m4[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(m4[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(m4[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(m4[0x18..0x20].try_into().expect("")),
                        ],
                        t: [3, 0],
                        f: true,
                    }
                ],
                vec![
                    H512::from_str("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
                    .expect("BLAKE2F compression function output is 64-bytes")
                ],
            )
        };
    }

    #[derive(Default)]
    pub struct Blake2fTestCircuit<F> {
        pub inputs: Vec<Blake2fWitness>,
        pub outputs: Vec<H512>,
        pub _marker: PhantomData<F>,
    }

    impl<F: FieldExt> Circuit<F> for Blake2fTestCircuit<F> {
        type Config = Blake2fConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
            let blake2f_table = Blake2fTable::construct(meta);
            Blake2fConfig::configure(meta, blake2f_table)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let chip = Blake2fChip::construct(config, self.inputs.clone());
            chip.load(&mut layouter)
        }
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use std::marker::PhantomData;

    use crate::dev::{Blake2fTestCircuit, INPUTS_OUTPUTS};

    #[test]
    fn test_blake2f_circuit() {
        let (inputs, outputs) = INPUTS_OUTPUTS.clone();

        let circuit: Blake2fTestCircuit<Fr> = Blake2fTestCircuit {
            inputs,
            outputs,
            _marker: PhantomData,
        };

        let k = 8;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
