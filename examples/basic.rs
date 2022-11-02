//! # Basic example
//!
//! This example shows a basic usage of the `vrf-rs` crate:
//!
//! 1. Instantiate the `ECVRF` by specifying the `CipherSuite`
//! 2. Generate a VRF proof by using the `prove()` function
//! 3. (Optional) Convert the VRF proof to a hash (e.g. to be used as pseudo-random value)
//! 4. Verify a VRF proof by using `verify()` function


//use vrf::openssl::{CipherSuite, ECVRF};
//use vrf::VRF;
use ecvrf::openssl::{CipherSuite, ECVRF};
use ecvrf::VRF;

fn main() {
     let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();

    // Inputs: Secret Key, Public Key (derived) & Message
    //let privkehex = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
    let privkeyhex = "945dbf86c04f14363f13e2bd2c4ad1fdfab04c38f3f1b07953c0b1e35ae76fab";
    let samplePubkey = "0x89454228068c1290f1883eff3cd545b89555a16ae27ce9a8da00e9bdcf8af4f2b2ee295e49bdaccad51364fb32119ced47b7c7504deb5f676951f9db455a9a36";
    let secret_key =
        hex::decode(privkeyhex).unwrap();
    let public_key = vrf.derive_public_key(&secret_key).unwrap();
    println!("public_key vec len {}",public_key.len());
    let pubkhex = hex::encode(&public_key);
    println!("sample {}",samplePubkey);
    println!("hexdec {},len:{}",pubkhex,pubkhex.len());
    let message: &[u8] = b"sample";

    // VRF proof and hash output
    let pi = vrf.prove(&secret_key, &message).unwrap();
    let hash = vrf.proof_to_hash(&pi).unwrap();
    println!("Generated VRF proof: {}", hex::encode(&pi));
    println!("proof len {}",pi.len() );

    // VRF proof verification (returns VRF hash output)
    let beta = vrf.verify(&public_key, &pi, &message);

    match beta {
        Ok(beta) => {
            println!("VRF proof is valid!\nHash output: {}", hex::encode(&beta));
            assert_eq!(hash, beta);
        }
        Err(e) => {
            println!("VRF proof is not valid: {:?}", e);
        }
    }
}
