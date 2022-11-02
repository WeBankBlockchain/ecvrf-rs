use std::ffi::{c_char, c_int, c_long, CStr};

use crate::openssl::{CipherSuite, ECVRF};
use crate::VRF;

/*将基本的vrf方法封装为ffi,供上层调用，
 接口字段和[u8]/vec相关的，规整为hex字符串类型，以便调用和调试，采用hex::encode/decode转译
 接口里的debuglevel是纯helper字段，置为1时，让rust代码打印调试信息到屏幕上（可以修改为日志）
 错误码定义：
 1xx为输入参数的错误序列
 2xx为vrf库调用本身的错误序列
 3xx为输出参数的错误序列

*** 举例：JAVA端调用的JNA代码：
#-------------------------------
先定义接口类：
    class LibECVrf extends Library{
        int prove_hex(String sk, String preSeed, Pointer outbuffer, long buffersize, int debuglevel);
        //pi即prove的结果，preseed是数据,公钥应依赖vrf库从私钥重新生成，而不是使用默认算法生成的公钥
        int verify_hex(String pk, String pi,String preSeed, Pointer outbuffer,long buffersize,int debuglevel);
        int derive_public_key_hex(String privkey,Pointer outbuffer,long buffersize,int debuglevel);
    }
加载动态库的核心代码
    ...通过classpath定位、配置文件等方式获得libFilePath，库默认名字为 libecvrf.so/vrecvrf.dll/libecvrf.dylib等
        LibECVrf  ecvrf = Native.loadLibrary(libFilePath, LibECVR.class);
* tips：如加载失败，可以将Native.loadlibrary()改成System.load()调试，错误信息更加精准（如路径不对，以及比较隐藏的依赖库版本问题等）
#-------------------------------
java端调用示例：
    long buffersize = 200; //分配内存空间，传入ffi方法
    Pointer outbuffer = new Memory(buffersize);
    int resk1 = ecvrf.prove_hex(hexkey, actualSeed, outbuffer, buffersize, debuglevel);
    if (resk1 < 0) {
        throw new VRFException(String.format("VRF Prove error %s", resk1));
    }
    resstr = new String(outbuffer.getByteArray(0, resk1));

*/
/*
todo:将ecvrf实例按曲线类型为key做缓存，避免多次初始化加载。
*/

#[no_mangle]
pub unsafe extern "C" fn prove_hex(privkey: *const c_char, alpha: *const c_char,
                                   outbuffer: *mut c_char, buffersize: c_long, debuglevel: c_int) -> c_long {
    let strprivkey = CStr::from_ptr(privkey);
    let stralpha = CStr::from_ptr(alpha);
    if debuglevel > 0 {
        println!("[ECVR.Prove] strin 1 len:{} - {}", &strprivkey.to_str().unwrap().len(), &strprivkey.to_str().unwrap());
        println!("[ECVR.Prove] strin 2 len:{} - {}", &stralpha.to_str().unwrap().len(), &stralpha.to_str().unwrap());
    }

    let xres = hex::decode(strprivkey.to_bytes());
    if xres.is_err() {
        if debuglevel > 0 {
            println!("[ECVR.Prove]input str 1 hex format error: {:?}", xres.err().unwrap());
            return -101;
        }
    }
    let x = xres.unwrap();
    let ares = hex::decode(stralpha.to_bytes());
    if ares.is_err() {
        if debuglevel > 0 {
            println!("[ECVR.Prove]input str 2 hex format error: {:?}", ares.err().unwrap());
            return -102;
        }
    }
    let a = ares.unwrap();
    //调用vrf库
    let vrfres = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI);
    if vrfres.is_err() {
        return -200;
    }
    let mut vrf = vrfres.unwrap();
    let proveres = vrf.prove(x.as_slice(), a.as_slice());
    if proveres.is_err() {
        return -201;
    }
    let provestr = hex::encode(proveres.unwrap());
    //生成的结果应该是81个字节bytes，162字节的 hex
    let proverlen = provestr.len();
    if debuglevel > 0 {
        println!("[ECVR.Prove] provestr len:{} , {}", proverlen, provestr);
    }

    if proverlen as c_long > buffersize {
        return -301;
    }
    provestr.as_ptr().copy_to(outbuffer as *mut u8, proverlen);
    return proverlen as c_long;
}


#[no_mangle]
pub unsafe extern "C" fn verify_hex(publickey: *const c_char, pi: *const c_char, alpha: *const c_char, outbuffer: *mut c_char, buffersize: c_long, debuglevel: c_int) -> c_long {
    let strpubkey = CStr::from_ptr(publickey);
    let strpi = CStr::from_ptr(pi);
    let stralpha = CStr::from_ptr(alpha);

    if debuglevel > 0 {
        println!("[ECVR.Verify]strpubkey : {:?}", strpubkey);
        println!("[ECVR.Verify]strpi : {:?}", strpi);
        println!("[ECVR.Verify]stralpha {:?}", stralpha)
    }

    let xres = hex::decode(strpubkey.to_bytes());
    if xres.is_err() {
        if debuglevel > 0 {
            println!("[ECVR.Verify]input str 1 hex format error: {:?}", xres.err().unwrap());
            return -101;
        }
    }
    let x = xres.unwrap();

    let pires = hex::decode(strpi.to_bytes());
    if pires.is_err() {
        if debuglevel > 0 {
            println!("[ECVR.Verify]input str 2 hex format error: {:?}", pires.err().unwrap());
            return -102;
        }
    }
    let p = pires.unwrap();


    let ares = hex::decode(stralpha.to_bytes());
    if ares.is_err() {
        if debuglevel > 0 {
            println!("[IN RUST]input str 3 hex format error: {:?}", ares.err().unwrap());
            return -103;
        }
    }
    let a = ares.unwrap();
    let vrfres = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI);
    if vrfres.is_err() {
        return -200;
    }
    let mut vrf = vrfres.unwrap();
    let verifyres = vrf.verify(x.as_slice(), p.as_slice(), a.as_slice());
    if verifyres.is_err() {
        return -201;
    }
    let verifydata = verifyres.unwrap();
    let hexverifydata = hex::encode(verifydata);
    let datalen = hexverifydata.len();
    if debuglevel > 0 {
        println!("[ECVR.Verify] verify data len: {} , {}", datalen, hexverifydata);
    }
    if datalen as c_long > buffersize {
        return -301;
    }
    hexverifydata.as_ptr().copy_to(outbuffer as *mut u8, datalen);
    return datalen as c_long;
}

#[no_mangle]
pub unsafe extern "C" fn derive_public_key_hex(secretkey: *const c_char, outbuffer: *mut c_char, buffersize: c_long, debuglevel: c_int) -> c_long
{
    let strkey = CStr::from_ptr(secretkey);
    let xres = hex::decode(strkey.to_bytes());
    if xres.is_err() {
        if debuglevel > 0 {
            println!("[ECVR.derive_pubkey]input str 1 hex format error: {:?}", xres.err().unwrap());
            return -101;
        }
    }
    let x = xres.unwrap();
    let vrfres = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI);
    if vrfres.is_err() {
        return -200;
    }
    let mut vrf = vrfres.unwrap();

    let pubkeyres = vrf.derive_public_key(x.as_slice());
    if pubkeyres.is_err() {
        return -201;
    }
    let pubkey = pubkeyres.unwrap();
    let pubkeystr = hex::encode(pubkey);
    let datalen = pubkeystr.len();
    if debuglevel > 0 {
        println!("[ECVR.derive_pubkey] derive_public_key_hex pubkeyhex len:{} , {}", datalen, pubkeystr);
    }
    if datalen as c_long > buffersize {
        return -301;
    }
    pubkeystr.as_ptr().copy_to(outbuffer as *mut u8, datalen);
    return datalen as c_long;
}


#[no_mangle]
pub unsafe extern "C" fn proof_to_hash_hex(proof: *const c_char, outbuffer: *mut c_char, buffersize: c_long, debuglevel: c_int) -> c_long
{
    let strproof = CStr::from_ptr(proof);
    let xres = hex::decode(strproof.to_bytes());
    if xres.is_err() {
        if debuglevel > 0 {
            println!("[ECVR.derive_pubkey]input str 1 hex format error: {:?}", xres.err().unwrap());
            return -101;
        }
    }
    let proofbytes = xres.unwrap();
    let vrfres = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI);
    if vrfres.is_err() {
        return -200;
    }
    let mut vrf = vrfres.unwrap();

    let hashres = vrf.proof_to_hash(proofbytes.as_slice());
    if hashres.is_err() {
        return -201;
    }
    let _hash = hashres.unwrap();
    let hashstr = hex::encode(_hash);
    let datalen = hashstr.len();
    if debuglevel > 0 {
        println!("[ECVR.proof_to_hash] hash str len:{} , {}", datalen, hashstr);
    }
    if datalen as c_long > buffersize {
        return -301;
    }
    hashstr.as_ptr().copy_to(outbuffer as *mut u8, datalen);
    return datalen as c_long;
}