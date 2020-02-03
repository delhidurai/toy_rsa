// Utility crate that will enable the user to Encrypt and Decrypt a given message.
// Author Delhi Durai

//
use toy_rsa_lib::*;

/// constant fixed RSA encryption exponent E, this will be used across multiple functions.
const E: u64 = 65_537;

///Function Lambda calculates  Carmichael's totient function
fn lambda(p: u32, q: u32) -> u64 {
    let p_u64 = p as u64;
    let q_u64: u64 = q as u64;
    lcm(p_u64 - 1, q_u64 - 1)
}
/// Public Function genkey calls rsa_prime() function in toy_rsa_lib and generates two prime numbers
/// Generate a pair of primes in the range 2**30..2**31
/// suitable for RSA encryption with exponent
pub fn genkey() -> (u32, u32) {
    let mut done = false;
    let mut p: u32 = 0;
    let mut q: u32 = 0;

    while !done {
        p = rsa_prime();
        q = rsa_prime();
        let lcm = lambda(p, q);
        let gcd = gcd(E, lcm);
        if (lcm > E) && (gcd == 1) {
            done = true;
        }
    }

    (p, q)
}

// Public Function encrypt takes Public key and Message as its parameter, it calls modexp() function in toy_rsa_lib and encrypts the given message.
pub fn encrypt(key: u64, msg: u32) -> u64 {
    let msg_u64: u64 = msg as u64;
    modexp(msg_u64, E, key)
}
//  Function encrypt takes Public key and Message as its parameter, it calls modexp() function in toy_rsa_lib and encrypts the given message.
fn inverse(lcm: u64, public_key: u64, msg: u64) -> u64 {
    let d = modinverse(E, lcm);
    modexp(msg, d, public_key)
}

// Public Function decrypt takes private keys and Message as its parameter, it calls mod inverse() function in toy_rsa_lib and decrypts the given message.
pub fn decrypt(key: (u64, u64), msg: u64) -> u64 {
    let (p, q) = key;
    let p_u32: u32 = p as u32;
    let q_u32: u32 = q as u32;
    let lcm = lambda(p_u32, q_u32);
    let public_key: u64 = p * q;
    inverse(lcm, public_key, msg)
}
