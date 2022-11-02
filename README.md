# Elliptic vrf-rs
[![](https://img.shields.io/crates/v/vrf.svg)](https://crates.io/crates/vrf) [![](https://docs.rs/vrf/badge.svg)](https://docs.rs/vrf) [![](https://github.com/witnet/vrf-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/witnet/vrf-rs/actions/workflows/rust.yml)

**Fork from（MIT license）: https://github.com/witnet/vrf-rs**

##  概述
基础库实现了几种曲线的vrf (SECP256K1_SHA256_TAI等)。

本项目扩展是将基本的vrf方法封装为ffi,供上层调用，

项目里的[src/vrf_ffi.rs](src/vrf_ffi.rs),采用**SECP256K1_SHA256_TAI**曲线。如需采用其他曲线，可以自行修改。

## ffi接口简单约定
* 接口字段和[u8]/vec相关的，规整为hex字符串类型，以便调用和调试，采用hex::encode/decode转译
* 接口里的debuglevel是纯helper字段，置为1时，让rust代码打印调试信息到屏幕上（可以修改为日志）
* 错误码定义：
``` 
    1xx为输入参数的错误序列
    2xx为vrf库调用本身的错误序列
    3xx为输出参数的错误序列
```
## 举例：JAVA端调用采用JNA接口模式：
### 先定义接口类：
```
    class LibECVrf extends Library{
        int prove_hex(String sk, String preSeed, Pointer outbuffer, long buffersize, int debuglevel);
        //pi即prove的结果，preseed是数据,公钥应依赖vrf库从私钥重新生成，而不是使用默认算法生成的公钥
        int verify_hex(String pk, String pi,String preSeed, Pointer outbuffer,long buffersize,int debuglevel);
        int derive_public_key_hex(String privkey,Pointer outbuffer,long buffersize,int debuglevel);
    }
```    
### 加载动态库的核心代码
    ...通过classpath定位、配置文件等方式获得libFilePath，库默认名字为 libecvrf.so/vrecvrf.dll/libecvrf.dylib等
        LibECVrf  ecvrf = Native.loadLibrary(libFilePath, LibECVR.class);

* Tips：如加载失败，可以将Native.loadlibrary()改成System.load()调试，错误信息更加精准（如路径不对，以及比较隐藏的依赖库版本问题等）

### java端调用示例：
```    
    long buffersize = 200; //分配内存空间，以待传入ffi方法,prove的字节数为81，转hex后为162
    Pointer outbuffer = new Memory(buffersize);
    int resk1 = ecvrf.prove_hex(hexkey, actualSeed, outbuffer, buffersize, debuglevel);
    if (resk1 < 0) {
        throw new VRFException(String.format("VRF Prove error %s", resk1));
    }
    resstr = new String(outbuffer.getByteArray(0, resk1));
```

## 附：上游开源项目说明:
* (首先，致谢原作者)

`vrf-rs` is an open source implementation of Verifiable Random Functions (VRFs) written in Rust.

_DISCLAIMER: This is experimental software. Be careful!_

The library can be built using `cargo` and the examples can be executed with:

```bash
cargo build
cargo run --example <example_name>
```

## Elliptic Curve VRF

This module uses the OpenSSL library to offer Elliptic Curve Verifiable Random Function (VRF) functionality.

It follows the algorithms described in:

* [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
* [RFC6979](https://tools.ietf.org/html/rfc6979)

Currently the supported cipher suites are:

* `P256_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `secp256r1` curve (aka `NIST P-256`).
* `K163_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `sect163k1` curve (aka `NIST K-163`).
* `SECP256K1_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `secp256k1` curve.

### Example

Create and verify a VRF proof by using the cipher suite `SECP256K1_SHA256_TAI`:

```rust
use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;

fn main() {
    // Initialization of VRF context by providing a curve
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    // Inputs: Secret Key, Public Key (derived) & Message
    let secret_key =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let public_key = vrf.derive_public_key(&secret_key).unwrap();
    let message: &[u8] = b"sample";
    
    // VRF proof and hash output
    let pi = vrf.prove(&secret_key, &message).unwrap();
    let hash = vrf.proof_to_hash(&pi).unwrap();

    // VRF proof verification (returns VRF hash output)
    let beta = vrf.verify(&public_key, &pi, &message);
}
```

A complete example can be found in [examples/basic.rs](https://github.com/witnet/vrf-rs/blob/master/examples/basic.rs). It can be executed with:

```bash
cargo run --example basic
```

## Adding unsupported cipher suites

This library defines a `VRF` trait which can be extended in order to use different curves and algorithms.

```rust
pub trait VRF<PublicKey, SecretKey> {
    type Error;

    fn prove(&mut self, x: SecretKey, alpha: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn verify(&mut self, y: PublicKey, pi: &[u8], alpha: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
```

## License

`vrf-rs` is published under the [MIT license][license].

[license]: https://github.com/witnet/vrf-rs/blob/master/LICENSE