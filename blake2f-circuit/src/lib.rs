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
    ///////////////////////////////////////////////////////////////////////////
    //
    ///////////////////////////////////////////////////////////////////////////
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
    ///////////////////////////////////////////////////////////////////////////
    //
    ///////////////////////////////////////////////////////////////////////////
    table: Blake2fTable,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Blake2fConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, table: Blake2fTable) -> Self {
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
pub struct Blake2fChip<F> {
    config: Blake2fConfig<F>,
}

impl<F: FieldExt> Blake2fChip<F> {
    pub fn construct(config: Blake2fConfig<F>) -> Self {
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

#[cfg(any(feature = "test", test))]
pub mod dev {}

#[cfg(test)]
mod tests {}
