use rand::rngs::OsRng;
use rand::RngCore;
use hex;
use hex::{encode, decode};
use pyo3::pyfunction;


fn prepend_nonce(vec: &mut Vec<u8>, nonce: [u32; 2]) {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&nonce[0].to_le_bytes());
    bytes.extend_from_slice(&nonce[1].to_le_bytes());

    vec.splice(0..0, bytes);
}


fn _encrypt(key: [u32; 8], nonce: [u32; 2],  mut plaintext: &[u8]) -> Vec<u8> {
    let len = plaintext.len();
    let mut ciphertext = vec![0u8; len];
    let num_blocks = (len + 63) / 64;
    let mut ctr= 0u64;
    let mut keystream;



    for i in 0..num_blocks {
        keystream = chacha20_block(key, ctr, nonce);

        let start = i * 64;
        let end = (start + 64).min(len);

        for j in start..end {
            ciphertext[j] = plaintext[j] ^ keystream[j - start];

        }
        ctr += 1;
    }

    return ciphertext;

}


fn chacha20_block(key: [u32; 8], ctr: u64, nonce: [u32; 2]) -> [u8; 64] {
    const CONST0: u32 = 0x61707865;
    const CONST1: u32 = 0x3320646e;
    const CONST2: u32 = 0x79622d32;
    const CONST3: u32 = 0x6b206574;

    let ctr = u64_to_u32_pair_le(ctr);

    let state: [u32; 16] = [
        CONST0, CONST1, CONST2, CONST3,
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        ctr[0], ctr[1], nonce[0], nonce[1]
    ];

    let mut x = state;

    for _ in 0..10 {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);

        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1,  6, 11, 12);
        quarter_round(&mut x, 2,  7,  8, 13);
        quarter_round(&mut x, 3,  4,  9, 14);
    }

    let mut keystream = [0u8; 64];

    for i in 0..16 {
        keystream[(4 * i)..(4 * i + 4)].copy_from_slice(&state[i].wrapping_add(x[i]).to_le_bytes());
    }


    return keystream;
}

fn u64_to_u32_pair_le(value: u64) -> [u32; 2] {
    [(value & 0xFFFFFFFF) as u32, (value >> 32) as u32]
}

fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);  x[d] ^= x[a];  x[d] = x[d].rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);  x[b] ^= x[c];  x[b] = x[b].rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);  x[d] ^= x[a];  x[d] = x[d].rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);  x[b] ^= x[c];  x[b] = x[b].rotate_left(7);
}



fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

fn u8_to_u32_array_le(bytes: [u8; 32]) -> [u32; 8] {
    let mut result = [0u32; 8];
    for i in 0..8 {
        result[i] = u32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
    }
    result
}

fn array_to_hex_string(array: [[u8; 4]; 4]) -> String {
    array
        .iter()
        .flat_map(|row| row.iter())
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

#[pyfunction]
pub fn chacha20_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut array_key = [0u8; 32];
    array_key.copy_from_slice(key);
    let nonce = [OsRng.next_u32(), OsRng.next_u32()];
    let mut ciphertext = _encrypt(u8_to_u32_array_le(array_key), nonce, plaintext);
    prepend_nonce(&mut ciphertext, nonce);
    return ciphertext;
}


#[pyfunction]
pub fn chacha20_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut array_key = [0u8; 32];
    array_key.copy_from_slice(key);
    let nonce = [
        u32::from_le_bytes(ciphertext[0..4].try_into().unwrap()),
        u32::from_le_bytes(ciphertext[4..8].try_into().unwrap()),
    ];
    let plaintext = _encrypt(u8_to_u32_array_le(array_key), nonce, &ciphertext[8..]);
    return plaintext;
}