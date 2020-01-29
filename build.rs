extern crate bindgen;

fn main() {
    println!("cargo:rustc-link-lib=sodium");
    println!("cargo:rustc-link-lib=zstd");
    println!("cargo:rerun-if-changed=src/sodium/wrapper.h");

    bindgen::builder()
        .header("src/sodium/wrapper.h")
        .whitelist_function("crypto_secretstream_.*")
        .whitelist_function("randombytes_((buf.*)|(uniform)|(random))")
        .whitelist_function("sodium_(init|increment)")
        .whitelist_function("crypto_box_(keypair|easy|open_easy)")
        .whitelist_function("crypto_sign(_open|_keypair)?")
        .whitelist_function("crypto_sign_(verify_)?detached")
        .whitelist_function("crypto_generichash_(init|update|final|statebytes)")
        .whitelist_function("crypto_aead_xchacha20poly1305_ietf_.+")
        .whitelist_function("crypto_kdf_(keygen|derive_from_key)")
        .whitelist_var("crypto_kdf_.+")
        .whitelist_var("crypto_aead_xchacha20poly1305_ietf_.+")
        .whitelist_var("crypto_secretstream_xchacha20poly1305_(A|HEADER|KEY)BYTES")
        .whitelist_var("crypto_secretstream_xchacha20poly1305_TAG_.*")
        .whitelist_var("crypto_box_(PUBLICKEY|SECRETKEY|MAC|NONCE)BYTES")
        .whitelist_var("crypto_generichash_(STATE|KEY)?BYTES")
        .whitelist_var("crypto_sign_(PUBLICKEY|SECRETKEY)?BYTES")
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
