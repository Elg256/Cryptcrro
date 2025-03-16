// maturin develop --release
//


use rand::rngs::OsRng;
use rand::RngCore;
use num_bigint::BigUint;
use num_bigint::{BigInt, Sign,ToBigInt};
use num_traits::Zero;
use num_traits::One;
use num_traits::FromPrimitive;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use pyo3::types::{PyInt, PyTuple, PyLong};

use crate::arith::modinv;
use crate::secp256k1::{mul_points, add_point, Point};



#[pyfunction]
pub fn check_sig(public_key: &PyTuple, sig: &PyTuple, hash_msg: &PyLong)-> BigInt{
    let n = BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
    let generator_point = Point {
        x: BigInt::parse_bytes(b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).unwrap(),
        y: BigInt::parse_bytes(b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16).unwrap(),
    };

    let hash_msg_big:BigInt = hash_msg.extract::<BigInt>().unwrap();

    let x_sig = sig.get_item(0).unwrap();  // Cela donne un `&PyAny`

    let x_sig: BigInt = x_sig.extract::<BigInt>().unwrap();  // Convertir en BigInt
    let y_sig: BigInt = sig.get_item(1).unwrap().extract::<BigInt>().unwrap();

    let x_pubk: BigInt = public_key.get_item(0).unwrap().extract::<BigInt>().unwrap();
    let y_pubk: BigInt = public_key.get_item(1).unwrap().extract::<BigInt>().unwrap();

    let public_key_point = Point{x:x_pubk, y:y_pubk};
    let s_inv = modinv(&y_sig, &n);
    let u1 = (&hash_msg_big * &s_inv) % &n;
    let u2 = (&x_sig * s_inv) % &n;

    let point1 = mul_points(&u1, &generator_point);

    let point2 = mul_points(&u2, &public_key_point);

    let result = add_point(&point1, &point2);

    return result.x;
}

#[pyfunction]
pub fn create_ecdsa_sig(private_key: &PyInt, hash_msg: &PyInt) -> PyResult<(PyObject, PyObject)>{
    let n = BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
    let generator_point = Point {
        x: BigInt::parse_bytes(b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).unwrap(),
        y: BigInt::parse_bytes(b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16).unwrap(),
    };

    let mut cs_generate_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut cs_generate_bytes);
    let random_int = BigInt::from_bytes_be(Sign::Plus, &cs_generate_bytes);

    let random_point = mul_points(&random_int, &generator_point);

    let hash_msg_big: BigInt = match hash_msg.extract::<BigInt>() {
        Ok(value) => value,
        Err(e) => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Failed to extract hash_msg as BigInt: {:?}", e))),
    };
    let private_key_big: BigInt = private_key.extract::<BigInt>().unwrap();


    let x_sig = random_point.x % &n;
    let y_sig = ((&hash_msg_big + &private_key_big * &x_sig) * modinv(&random_int, &n)) % &n;


    return Python::with_gil(|py| {
        Ok((x_sig.to_object(py), y_sig.to_object(py)))});

}
