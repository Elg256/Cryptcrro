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
use pyo3::types::{PyLong, PyTuple};


#[pyclass]
struct Point{
    x: BigInt,
    y: BigInt,
}

fn modinv(n: &BigInt, p: &BigInt) -> BigInt {
    if p.is_one() { return BigInt::one() }

    let (mut a, mut m, mut x, mut inv) = (n.clone(), p.clone(), BigInt::zero(), BigInt::one());

    
    while a < BigInt::zero() { a += p } // may be put after the while
    
    while a > BigInt::one() {
        let div = &a / &m;
        let rem = &a % &m;
        inv -= div * &x;
        a = rem;
        std::mem::swap(&mut a, &mut m);
        std::mem::swap(&mut x, &mut inv);
    }
    
    

    if inv < BigInt::zero() { inv += p }

    inv
}

#[pyfunction]
fn ecies_mul_points(scalar: &PyLong, point: &PyTuple) -> PyResult<(PyObject, PyObject)>{

    let scalar_big:BigInt = scalar.extract().unwrap();

    let x: BigInt = point.get_item(0).unwrap().extract::<BigInt>().unwrap();
    let y: BigInt = point.get_item(1).unwrap().extract::<BigInt>().unwrap();

    let struct_point = Point{x:x, y:y};

    let result = mul_points(&scalar_big, &struct_point);

    return Python::with_gil(|py| {
        Ok((result.x.to_object(py), result.y.to_object(py)))});

}

#[pyfunction]
fn check_sig(public_key: &PyTuple, sig: &PyTuple, hash_msg: &PyLong)-> BigInt{
    let n = BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
    let generator_point = Point {
        x: BigInt::parse_bytes(b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).unwrap(),
        y: BigInt::parse_bytes(b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16).unwrap(),
    };

    let hash_msg_big:BigInt = hash_msg.extract::<BigInt>().unwrap();

    let x_sig: BigInt = sig.get_item(0).unwrap().extract::<BigInt>().unwrap();
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
fn create_ecdsa_sig(private_key: &PyLong, hash_msg: &PyLong) -> PyResult<(PyObject, PyObject)>{
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



#[pyfunction]
fn generate_public_key(private_key: &PyLong) -> PyResult<(PyObject, PyObject)>{ //PyResult<(PyObject, PyObject)>
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


fn mul_points(scalar: &BigInt, point: &Point) -> Point {
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

#[pyfunction]
fn generate_public_key_without(private_key: &PyLong) -> PyResult<(PyObject, PyObject)> {
    let private_key: BigInt = private_key.extract().unwrap();
    //We are using the double and add method

    let generator_point = Point {
        x:BigInt::parse_bytes(b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).unwrap(),
        y:BigInt::parse_bytes(b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16).unwrap(),
    };

    let mut result = Point{x:BigInt::zero(), y:BigInt::zero()};

    let binary_private_key = private_key.to_str_radix(2);

    for bit in binary_private_key.chars(){

        result = double_point(&result);

        if bit == '1'{
            result = add_point(&result, &generator_point);

        }

    }


    return Python::with_gil(|py| {
        Ok((result.x.to_object(py), result.y.to_object(py)))
    });
}


#[pyfunction]
fn generate_private_key() -> BigInt{
    let mut cs_generate_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut cs_generate_bytes);
    let private_key = BigInt::from_bytes_be(Sign::Plus,&cs_generate_bytes);

    return private_key;
}



fn add_point(point1: &Point, point2: &Point) -> Point{

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

fn double_point(point: &Point) -> Point{

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


#[pymodule]
fn rust_cryptcrro(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_private_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(create_ecdsa_sig, m)?)?;
    m.add_function(wrap_pyfunction!(check_sig, m)?)?;
    m.add_function(wrap_pyfunction!(ecies_mul_points, m)?)?;
    Ok(())
}