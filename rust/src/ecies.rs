use num_bigint::BigInt;
use pyo3::{pyfunction, PyObject, PyResult, Python};
use pyo3::types::{PyInt, PyTuple};
use pyo3::prelude::*;

use crate::secp256k1::mul_points;

#[pyfunction]
pub fn ecies_mul_points(scalar: &PyInt, point: &PyTuple) -> PyResult<(PyObject, PyObject)>{

    let scalar_big:BigInt = scalar.extract().unwrap();

    let x: BigInt = point.get_item(0).unwrap().extract::<BigInt>().unwrap();
    let y: BigInt = point.get_item(1).unwrap().extract::<BigInt>().unwrap();

    let struct_point = crate::secp256k1::Point {x:x, y:y};

    let result = mul_points(&scalar_big, &struct_point);

    return Python::with_gil(|py| {
        Ok((result.x.to_object(py), result.y.to_object(py)))});

}