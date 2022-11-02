use std::ffi::{c_char, CString};

//use ecvrf::openssl::{CipherSuite, ECVRF};
use ecvrf::vrf_ffi::{derive_public_key_hex, proof_to_hash_hex, prove_hex, verify_hex};

//将rust的str转成C指针
#[macro_export]
macro_rules! str2p {
    ($x:expr) => {
        CString::new($x).unwrap().as_ptr() as *const c_char
    };
}
fn main() {
    let privkeyhex = "945dbf86c04f14363f13e2bd2c4ad1fdfab04c38f3f1b07953c0b1e35ae76fab";
    //let privkeybin = hex::decode(privkeyhex).unwrap();
    //let samplePubkey = "89454228068c1290f1883eff3cd545b89555a16ae27ce9a8da00e9bdcf8af4f2b2ee295e49bdaccad51364fb32119ced47b7c7504deb5f676951f9db455a9a36";
    let data = "abcde12345";

    unsafe {
        let outbuffer: [u8; 500] = [0; 500];
        //1) prove -------------------->
        let r = prove_hex(str2p!(privkeyhex), str2p!(data),
                             outbuffer.as_ptr() as *mut c_char, 500, 1);
        let pistr = String::from_utf8_lossy(&outbuffer[0..r as usize]).clone();
        println!("prove result {}", pistr);
        println!("Generated VRF proof: {}", pistr);
        println!("proof len {}", pistr.len());
        //2) make proof to hash -------------------->
        let outbuffer: [u8; 500] = [0; 500];
        let r = proof_to_hash_hex(str2p!(pistr.to_string().as_str()),
                                  outbuffer.as_ptr() as *mut c_char,500,1);
        let _hash = String::from_utf8_lossy(&outbuffer[0..r as usize]).clone();

        //3) derive public key from privkey -------------------->
        let outbuffer: [u8; 500] = [0; 500];


        let r = derive_public_key_hex(str2p!(privkeyhex),
                                      outbuffer.as_ptr() as *mut c_char,
                                      500, 1);
        let public_key = String::from_utf8_lossy(&outbuffer[0..r as usize]).clone();
        println!("public_key vec len {},{}", public_key.len(),public_key);

        //4) verify -------------------->
        println!("start verify by pubkey :{}", public_key);
        let r = verify_hex(str2p!(public_key.to_string().as_str()),
                           str2p!(pistr.to_string().as_str()), str2p!(data),
                           outbuffer.as_ptr() as *mut c_char, 500, 1);
        if r < 0 {
            println!("verify_hex error ! code :{}", r);
        } else {
            let vs = String::from_utf8_lossy(&outbuffer[0..r as usize]);
            println!("verify ret {}, data:{}", vs.len(), vs.to_string());
            println!("hash is {}", _hash.to_string());
            println!("check eq:{}",vs.to_string().eq(&_hash.to_string()));
        }
    }
}