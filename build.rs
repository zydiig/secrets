extern crate bindgen;

fn main() {
    println!("cargo:rustc-link-lib=sodium");
    println!("cargo:rerun-if-changed=src/sodium/wrapper.h");

    let bindings = bindgen::builder()
        .header("src/sodium/wrapper.h")
        .whitelist_function("crypto_secretstream_.*")
        .whitelist_function("randombytes_((buf.*)|(uniform)|(random))")
        .whitelist_function("sodium_init")
        .whitelist_function("crypto_box_(keypair|easy|open_easy)")
        .whitelist_function("crypto_sign(_open|_keypair)?")
        .whitelist_function("crypto_sign_(verify_)?detached")
        .whitelist_function("crypto_generichash_(init|update|final|statebytes)")
        .whitelist_var("crypto_secretstream_xchacha20poly1305_(A|HEADER|KEY)BYTES")
        .whitelist_var("crypto_secretstream_xchacha20poly1305_TAG_.*")
        .whitelist_var("crypto_box_(PUBLICKEY|SECRETKEY|MAC|NONCE)BYTES")
        .whitelist_var("crypto_generichash_(STATE|KEY)?BYTES")
        .whitelist_var("crypto_sign_(PUBLICKEY|SECRETKEY)?BYTES")
        .layout_tests(false)
        .generate()
        .unwrap();
    bindings.write_to_file("src/sodium/_sodium.rs").unwrap();
}
