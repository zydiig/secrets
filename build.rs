extern crate bindgen;
extern crate cc;

fn main() {
    println!("cargo:rustc-link-lib=sodium");
    println!("cargo:rustc-link-lib=zstd");
    println!("cargo:rerun-if-changed=src/sodium/wrapper.h");

    cc::Build::new()
        .debug(true)
        .file("src/kyber/kem.c")
        .file("src/kyber/indcpa.c")
        .file("src/kyber/symmetric-shake.c")
        .file("src/kyber/poly.c")
        .file("src/kyber/polyvec.c")
        .file("src/kyber/randombytes.c")
        .file("src/kyber/fips202.c")
        .file("src/kyber/cbd.c")
        .file("src/kyber/ntt.c")
        .file("src/kyber/reduce.c")
        .file("src/kyber/verify.c")
        .include("src/kyber/")
        .compile("kyber");

    println!("cargo:rustc-link-lib=static=kyber");

    bindgen::builder()
        .header("src/kyber/api.h")
        .whitelist_function("pqcrystals_kyber1024_ref.+")
        .whitelist_var("pqcrystals_kyber1024_ref.+")
        .generate()
        .unwrap()
        .write_to_file("src/kyber/ffi.rs")
        .unwrap();

    bindgen::builder()
        .header("src/sodium/wrapper.h")
        .whitelist_function("crypto_secretstream_.*")
        .whitelist_function("crypto_kx_.*")
        .whitelist_function("randombytes_((buf.*)|(uniform)|(random))")
        .whitelist_function("sodium_(init|increment)")
        .whitelist_function("crypto_box_(keypair|easy|open_easy)")
        .whitelist_function("crypto_secretbox_.+")
        .whitelist_function("crypto_sign(_open|_keypair)?")
        .whitelist_function("crypto_sign_(verify_)?detached")
        .whitelist_function("crypto_generichash_(init|update|final|statebytes)")
        .whitelist_function("crypto_aead_xchacha20poly1305_ietf_.+")
        .whitelist_function("crypto_aead_aes256gcm_.+")
        .whitelist_function("crypto_kdf_(keygen|derive_from_key)")
        .whitelist_function("sodium_bin2hex")
        .whitelist_function("crypto_pwhash")
        .whitelist_var("crypto_secretbox_.+")
        .whitelist_var("crypto_pwhash_.+")
        .whitelist_var("crypto_kdf_.+")
        .whitelist_var("crypto_kx_.+")
        .whitelist_var("crypto_aead_xchacha20poly1305_ietf_.+")
        .whitelist_var("crypto_secretstream_xchacha20poly1305_(A|HEADER|KEY)BYTES")
        .whitelist_var("crypto_secretstream_xchacha20poly1305_TAG_.*")
        .whitelist_var("crypto_box_(PUBLICKEY|SECRETKEY|MAC|NONCE)BYTES")
        .whitelist_var("crypto_generichash_(STATE|KEY)?BYTES")
        .whitelist_var("crypto_sign_(PUBLICKEY|SECRETKEY)?BYTES")
        .whitelist_var("crypto_aead_aes256gcm_.+")
        .layout_tests(false)
        .generate()
        .unwrap()
        .write_to_file("src/sodium/_sodium.rs")
        .unwrap();
    bindgen::builder()
        .header("/usr/include/zstd.h")
        .whitelist_function("ZSTD_.+")
        .whitelist_var("ZSTD_.+")
        .generate_comments(false)
        .generate()
        .unwrap()
        .write_to_file("src/zstd/_zstd.rs")
        .unwrap();
}
