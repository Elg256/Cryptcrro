use pyo3::prelude::*;
mod aes_ctr;
pub mod ecdsa;
pub mod secp256k1;
pub mod arith;
mod ecies;
mod chacha20;


#[pymodule]
fn _rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(aes_ctr::aes256_ctr_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_ctr::aes256_ctr_decrypt, m)?)?;

    m.add_function(wrap_pyfunction!(chacha20::chacha20_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(chacha20::chacha20_decrypt, m)?)?;

    m.add_function(wrap_pyfunction!(secp256k1::generate_private_key, m)?)?;
    m.add_function(wrap_pyfunction!(secp256k1::generate_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa::create_ecdsa_sig, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa::check_sig, m)?)?;
    m.add_function(wrap_pyfunction!(ecies::ecies_mul_points, m)?)?;
    Ok(())
}
