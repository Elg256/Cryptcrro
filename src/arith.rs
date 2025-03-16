use num_bigint::BigInt;
use num_traits::Zero;
use num_traits::One;

pub fn modinv(n: &BigInt, p: &BigInt) -> BigInt {
    if p.is_one() { return BigInt::one() }

    let (mut a, mut m, mut x, mut inv) = (n.clone(), p.clone(), BigInt::zero(), BigInt::one());


    while a < BigInt::zero() { a += p }

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
