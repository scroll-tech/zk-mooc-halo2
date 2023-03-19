use halo2_proofs::{
    halo2curves::bn256::Fr,
    arithmetic::{FieldExt, Field},
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};

#[derive(Clone, Copy)]
pub struct ResiduePatternConfig {
    always_enabled: Selector, // This selector is always enabled to avoid ConstraintPoisoned errors.
    index_is_nonzero: Selector, // enabled iff index column is not zero.
    index: Column<Fixed>,     // repeats [0..length)

    value: Column<Advice>,       // value we're computing residue pattern for
    is_residue: Column<Advice>,  // binary column that is 1 iff value + index is a quadratic residue
    pattern: Column<Advice>,     // built up bit by bit from is_residue
    square_root: Column<Advice>, // square root of value + index if its a residue or nonresidue * (value + index) otherwise.
}

pub struct ResiduePatternChip<F> {
    length: usize,
    nonresidue: F,
    config: ResiduePatternConfig,
}

pub fn residue_pattern(x: Fr) -> u64 {
    (0u64..64)
        .map(|i| Option::<Fr>::from((x + Fr::from(i)).sqrt()).is_some())
        .fold(0, |pattern, is_residue| 2 * pattern + u64::from(is_residue))
}

impl ResiduePatternConfig {
    pub fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>, nonresidue: F) -> Self {
        let [always_enabled, index_is_nonzero] = [0; 2].map(|_| meta.selector());
        let index = meta.fixed_column();
        let [value, is_residue, pattern, square_root] = [0; 4].map(|_| meta.advice_column());

        meta.create_gate("value does not change if index is non-zero", |meta| {
            let index = meta.query_fixed(index, Rotation::cur());
            let value_current = meta.query_advice(value, Rotation::cur());
            let value_previous = meta.query_advice(value, Rotation::prev());
            vec![index * (value_current - value_previous)]
        });

        meta.create_gate("is_residue is binary", |meta| {
            let always_enabled = meta.query_selector(always_enabled);
            let is_residue = meta.query_advice(is_residue, Rotation::cur());
            vec![
                always_enabled * is_residue.clone() * (Expression::Constant(F::one()) - is_residue),
            ]
        });

        meta.create_gate("square_root^2 = value + index if is_residue", |meta| {
            let always_enabled = meta.query_selector(always_enabled);
            let is_residue = meta.query_advice(is_residue, Rotation::cur());
            let square_root = meta.query_advice(square_root, Rotation::cur());
            let square = meta.query_advice(value, Rotation::cur())
                + meta.query_fixed(index, Rotation::cur());
            vec![always_enabled * is_residue * (square_root.square() - square)]
        });

        meta.create_gate(
            "square_root^2 = nonresidue * (value + index) if not is_residue",
            |meta| {
                let always_enabled = meta.query_selector(always_enabled);
                let is_nonresidue =
                    Expression::Constant(F::one()) - meta.query_advice(is_residue, Rotation::cur());
                let fixed_nonresidue = Expression::Constant(nonresidue);
                let square_root = meta.query_advice(square_root, Rotation::cur());
                let nonresidue = meta.query_advice(value, Rotation::cur())
                    + meta.query_fixed(index, Rotation::cur());
                vec![
                    always_enabled
                        * is_nonresidue
                        * (square_root.square() - fixed_nonresidue * nonresidue),
                ]
            },
        );

        meta.create_gate(
            "current pattern = is_residue + 2 * previous pattern",
            |meta| {
                let index_is_nonzero = meta.query_selector(index_is_nonzero);
                let is_residue = meta.query_advice(is_residue, Rotation::cur());
                let pattern_current = meta.query_advice(pattern, Rotation::cur());
                let pattern_previous = meta.query_advice(pattern, Rotation::prev());
                vec![
                    index_is_nonzero
                        * (pattern_current
                            - Expression::Constant(F::from(2)) * pattern_previous
                            - is_residue),
                ]
            },
        );

        Self {
            index,
            value,
            is_residue,
            pattern,
            square_root,
            index_is_nonzero,
            always_enabled,
        }
    }
}

impl<F: FieldExt> ResiduePatternChip<F> {
    pub fn assign(&self, layouter: &mut impl Layouter<F>, values: &[F]) -> Result<Vec<u64>, Error> {
        layouter.assign_region(
            || "residue_pattern",
            |mut region| {
                let mut patterns = vec![];
                let mut offset = 0;
                for value in values.iter() {
                    patterns.push(self.assign_value(&mut region, offset, *value)?);
                    offset += self.length;
                }
                Ok(patterns)
            },
        )
    }

    fn assign_value(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: F,
    ) -> Result<u64, Error> {
        let config = self.config;
        let mut pattern = 0;
        let mut offset = offset;
        for index in 0u64..self.length.try_into().unwrap() {
            config.always_enabled.enable(region, offset)?;
            if index != 0 {
                config.index_is_nonzero.enable(region, offset)?;
            }

            let index = F::from(index);
            region.assign_fixed(|| "index", config.index, offset, || Value::known(index))?;

            region.assign_advice(|| "value", config.value, offset, || Value::known(value))?;

            let (is_residue, square_root) =
                if let Some(square_root) = Option::<F>::from((value + index).sqrt()) {
                    (true, square_root)
                } else {
                    (
                        false,
                        Option::<F>::from((self.nonresidue * (value + index)).sqrt()).unwrap(),
                    )
                };

            region.assign_advice(
                || "is_residue",
                config.is_residue,
                offset,
                || Value::known(if is_residue { F::one() } else { F::zero() }),
            )?;

            pattern = 2 * pattern + u64::from(is_residue);
            region.assign_advice(
                || "pattern",
                config.pattern,
                offset,
                || Value::known(F::from(pattern)),
            )?;

            region.assign_advice(
                || "square_root",
                config.square_root,
                offset,
                || Value::known(square_root),
            )?;

            offset += 1;
        }
        Ok(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        arithmetic::Field, circuit::SimpleFloorPlanner, dev::MockProver,
        plonk::Circuit,
    };

    #[derive(Default)]
    struct TestCircuit<F> {
        values: Vec<F>,
        length: usize,
        nonresidue: F,
    }

    impl<F: FieldExt> TestCircuit<F> {
        fn nonresidue() -> F {
            F::from(5)
        }
    }

    impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
        type Config = ResiduePatternConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            ResiduePatternConfig::configure(meta, Self::nonresidue())
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let chip = ResiduePatternChip {
                config,
                length: self.length,
                nonresidue: self.nonresidue,
            };
            chip.assign(&mut layouter, &self.values)?;
            Ok(())
        }
    }

    #[test]
    fn test_vectors() {
        assert_eq!(
            residue_pattern(Fr::zero()),
            0b1111101011001100101000001111010010011101000100001110111100110000
        );
        assert_eq!(
            residue_pattern(Fr::one()),
            0b1111010110011001010000011110100100111010001000011101111001100001
        );
        assert_eq!(
            residue_pattern(Fr::from(0x5234234)),
            0b110011011100010010000111110001011101000000000010111000101011110
        );
    }

    #[test]
    fn test_nonresidue() {
        assert_eq!(
            Option::<Fr>::from(TestCircuit::<Fr>::nonresidue().sqrt()),
            None
        );
    }

    #[test]
    fn test_residue_pattern_circuit() {
        let circuit = TestCircuit {
            values: vec![0.into(), 2323.into(), 124123123.into(), 3.into()],
            length: 64,
            nonresidue: TestCircuit::<Fr>::nonresidue(),
        };

        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
