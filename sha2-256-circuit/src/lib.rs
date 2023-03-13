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
pub struct Sha2Table {
    ///////////////////////////////////////////////////////////////////////////
    //
    ///////////////////////////////////////////////////////////////////////////
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
    ///////////////////////////////////////////////////////////////////////////
    //
    ///////////////////////////////////////////////////////////////////////////
    table: Sha2Table,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Sha2Config<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, table: Sha2Table) -> Self {
        ///////////////////////////////////////////////////////////////////////
        //
        ///////////////////////////////////////////////////////////////////////

        Self {
            table,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Sha2Chip<F> {
    config: Sha2Config<F>,
}

impl<F: FieldExt> Sha2Chip<F> {
    pub fn construct(config: Sha2Config<F>) -> Self {
        ///////////////////////////////////////////////////////////////////////
        //
        ///////////////////////////////////////////////////////////////////////

        Self { config }
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        ///////////////////////////////////////////////////////////////////////
        //
        ///////////////////////////////////////////////////////////////////////

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    use ethers_core::types::H256;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };

    #[derive(Default)]
    struct Sha2TestCircuit<F> {
        inputs: Vec<Vec<u8>>,
        outputs: Vec<H256>,
        _marker: PhantomData<F>,
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
            let chip = Sha2Chip::construct(config);
            chip.load(&mut layouter)
        }
    }

    #[test]
    fn test_sha2_circuit() {
        let (inputs, outputs): (Vec<Vec<u8>>, Vec<H256>) = [
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
            .unzip();

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
