// maturin develop --release
//

use rand::rngs::OsRng;
use rand::RngCore;
use num_bigint::{BigInt, Sign,ToBigInt};
use num_traits::Zero;
use num_traits::One;
use num_traits::FromPrimitive;
use pyo3::prelude::*;
use pyo3::types::PyInt;

use crate::arith::modinv as modinv;


#[pyclass]
pub struct Point{
    pub x: BigInt,
    pub y: BigInt,
}


#[pyfunction]
pub fn generate_public_key(private_key: &PyInt) -> PyResult<(PyObject, PyObject)>{
    Python::with_gil(|py| {
        let generator_point = Point {
            x: BigInt::parse_bytes(b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).unwrap(),
            y: BigInt::parse_bytes(b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16).unwrap(),
        };
        let private_key_big: BigInt = private_key.extract().unwrap();

        let public_key = mul_points(&private_key_big, &generator_point);

        return Python::with_gil(|py| {
            Ok((public_key.x.to_object(py), public_key.y.to_object(py)))
        });
    })
}

#[pyfunction]
pub fn generate_private_key() -> BigInt{
    let mut cs_generate_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut cs_generate_bytes);
    let private_key = BigInt::from_bytes_be(Sign::Plus,&cs_generate_bytes);

    return private_key;
}


pub fn mul_points(scalar: &BigInt, point: &Point) -> Point {
    //We are using the double and add method

    let mut result = Point{x:BigInt::zero(), y:BigInt::zero()};

    let mut r1 = Point { x: point.x.clone(), y: point.y.clone() };

    let binary_scalar = scalar.to_str_radix(2);

    //making this operation time constant but is still weak against FLUSH+RELOAD side-channel attack
    for bit in binary_scalar.chars(){

        if bit == '0'{
            r1 = add_point(&result, &r1);
            result = double_point(&result);

        }

        else{
            result = add_point(&result, &r1);
            r1 = double_point(&r1);
        }

    }

    return result;
}

pub fn add_point(point1: &Point, point2: &Point) -> Point{

    let p = BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap();

    let mut result = Point{x:BigInt::zero(), y:BigInt::zero()};

    if point1.x == BigInt::zero() && point1.y == BigInt::zero(){
        result.x = point2.x.clone();
        result.y = point2.y.clone();
        return result;
    }

    if point2.x == BigInt::zero() && point2.y == BigInt::zero(){
        result.x = point1.x.clone();
        result.y = point1.y.clone();
        return result;
    }

    if point1.x == point2.x && point1.y == point2.y{
        result = double_point(&point1);
        return result;
    }


    let s = ((&point1.y - &point2.y) * modinv(&(&point1.x - &point2.x), &p)) % &p;

    let t = ((&point2.y * &point1.x - &point1.y * &point2.x) * modinv(&(&point1.x - &point2.x), &p)) % &p;

    result.x = (&s.pow(2) - &point1.x - &point2.x) % &p;
    if result.x < BigInt::zero(){
        result.x += &p;
    }


    result.y = (- &s*(&s.pow(2) - &point1.x - &point2.x) - &t ) % &p;
    if result.y < BigInt::zero(){
        result.y += &p;
    }
    return result;
}

pub fn double_point(point: &Point) -> Point{

    let mut result = Point{x:BigInt::zero(), y:BigInt::zero()};

    if point.x == BigInt::zero() && point.y == BigInt::zero(){
        result.x = BigInt::parse_bytes(b"0", 10).unwrap();
        result.y = BigInt::parse_bytes(b"0", 10).unwrap();
        return result;

    }

    let p = BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap();

    let a = BigInt::from_u32(0).unwrap(); //with Secp256k1 a = 0 we put it for using this program with others curve

    let s = ((BigInt::from_u32(3).unwrap()*(&point.x).pow(2) + &a) * modinv(&(BigInt::from_u32(2).unwrap()*&point.y), &p) )% &p;

    result.x = (&s.pow(2) - BigInt::from_u32(2).unwrap()* &point.x) % &p;
    if result.x < BigInt::zero(){
        result.x += &p;
    }

    result.y = (&s * (&point.x - &result.x) - &point.y ) % &p;
    if result.y < BigInt::zero(){
        result.y += &p;
    }

    return result;
}
