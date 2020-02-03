// Stand alone executable module to run the toy_rsa crate


use std::env;
use toy_rsa::*;
// The fn is used to log error message.
fn error_with_msg(err_msg: &str) -> ! {
    eprintln!("Error occurred : {} ", err_msg);
    std::process::exit(1);
}
// Main method that will get the message as input from the user
fn main() {
    let args: Vec<String> = env::args().collect();
    let (p, q) = genkey();
    println!("The Private keys generated are p = {}, q= {}", p, q);
    let p_u64: u64 = p as u64;
    let q_u64: u64 = q as u64;
    let pk = p as u64 * q as u64;
    println!("Public Key: p * q = {}", pk);
    let msg: u32 = args[1]
        .parse()
        .unwrap_or_else(|_| error_with_msg("error when parsing the input"));
    println!("Input Message  {}", msg);
    let encrypted = encrypt(pk, msg);
    println!("Encrypted value is  {}", encrypted);
    let decrypted = decrypt((p_u64, q_u64), encrypted);
    println!("Decrypted = {}", decrypted);
}
