/* automatically generated by rust-bindgen */

pub const crypto_aead_aes256gcm_KEYBYTES: u32 = 32;
pub const crypto_aead_aes256gcm_NSECBYTES: u32 = 0;
pub const crypto_aead_aes256gcm_NPUBBYTES: u32 = 12;
pub const crypto_aead_aes256gcm_ABYTES: u32 = 16;
pub const crypto_aead_xchacha20poly1305_ietf_KEYBYTES: u32 = 32;
pub const crypto_aead_xchacha20poly1305_ietf_NSECBYTES: u32 = 0;
pub const crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: u32 = 24;
pub const crypto_aead_xchacha20poly1305_ietf_ABYTES: u32 = 16;
pub const crypto_box_PUBLICKEYBYTES: u32 = 32;
pub const crypto_box_SECRETKEYBYTES: u32 = 32;
pub const crypto_box_NONCEBYTES: u32 = 24;
pub const crypto_box_MACBYTES: u32 = 16;
pub const crypto_generichash_BYTES: u32 = 32;
pub const crypto_generichash_KEYBYTES: u32 = 32;
pub const crypto_kdf_blake2b_BYTES_MIN: u32 = 16;
pub const crypto_kdf_blake2b_BYTES_MAX: u32 = 64;
pub const crypto_kdf_blake2b_CONTEXTBYTES: u32 = 8;
pub const crypto_kdf_blake2b_KEYBYTES: u32 = 32;
pub const crypto_kdf_BYTES_MIN: u32 = 16;
pub const crypto_kdf_BYTES_MAX: u32 = 64;
pub const crypto_kdf_CONTEXTBYTES: u32 = 8;
pub const crypto_kdf_KEYBYTES: u32 = 32;
pub const crypto_kdf_PRIMITIVE: &'static [u8; 8usize] = b"blake2b\0";
pub const crypto_kx_PUBLICKEYBYTES: u32 = 32;
pub const crypto_kx_SECRETKEYBYTES: u32 = 32;
pub const crypto_kx_SEEDBYTES: u32 = 32;
pub const crypto_kx_SESSIONKEYBYTES: u32 = 32;
pub const crypto_kx_PRIMITIVE: &'static [u8; 14usize] = b"x25519blake2b\0";
pub const crypto_pwhash_argon2i_ALG_ARGON2I13: u32 = 1;
pub const crypto_pwhash_argon2i_BYTES_MIN: u32 = 16;
pub const crypto_pwhash_argon2i_PASSWD_MIN: u32 = 0;
pub const crypto_pwhash_argon2i_PASSWD_MAX: u32 = 4294967295;
pub const crypto_pwhash_argon2i_SALTBYTES: u32 = 16;
pub const crypto_pwhash_argon2i_STRBYTES: u32 = 128;
pub const crypto_pwhash_argon2i_STRPREFIX: &'static [u8; 10usize] = b"$argon2i$\0";
pub const crypto_pwhash_argon2i_OPSLIMIT_MIN: u32 = 3;
pub const crypto_pwhash_argon2i_OPSLIMIT_MAX: u32 = 4294967295;
pub const crypto_pwhash_argon2i_MEMLIMIT_MIN: u32 = 8192;
pub const crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE: u32 = 4;
pub const crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE: u32 = 33554432;
pub const crypto_pwhash_argon2i_OPSLIMIT_MODERATE: u32 = 6;
pub const crypto_pwhash_argon2i_MEMLIMIT_MODERATE: u32 = 134217728;
pub const crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE: u32 = 8;
pub const crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE: u32 = 536870912;
pub const crypto_pwhash_argon2id_ALG_ARGON2ID13: u32 = 2;
pub const crypto_pwhash_argon2id_BYTES_MIN: u32 = 16;
pub const crypto_pwhash_argon2id_PASSWD_MIN: u32 = 0;
pub const crypto_pwhash_argon2id_PASSWD_MAX: u32 = 4294967295;
pub const crypto_pwhash_argon2id_SALTBYTES: u32 = 16;
pub const crypto_pwhash_argon2id_STRBYTES: u32 = 128;
pub const crypto_pwhash_argon2id_STRPREFIX: &'static [u8; 11usize] = b"$argon2id$\0";
pub const crypto_pwhash_argon2id_OPSLIMIT_MIN: u32 = 1;
pub const crypto_pwhash_argon2id_OPSLIMIT_MAX: u32 = 4294967295;
pub const crypto_pwhash_argon2id_MEMLIMIT_MIN: u32 = 8192;
pub const crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE: u32 = 2;
pub const crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE: u32 = 67108864;
pub const crypto_pwhash_argon2id_OPSLIMIT_MODERATE: u32 = 3;
pub const crypto_pwhash_argon2id_MEMLIMIT_MODERATE: u32 = 268435456;
pub const crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE: u32 = 4;
pub const crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE: u32 = 1073741824;
pub const crypto_pwhash_ALG_ARGON2I13: u32 = 1;
pub const crypto_pwhash_ALG_ARGON2ID13: u32 = 2;
pub const crypto_pwhash_ALG_DEFAULT: u32 = 2;
pub const crypto_pwhash_BYTES_MIN: u32 = 16;
pub const crypto_pwhash_PASSWD_MIN: u32 = 0;
pub const crypto_pwhash_PASSWD_MAX: u32 = 4294967295;
pub const crypto_pwhash_SALTBYTES: u32 = 16;
pub const crypto_pwhash_STRBYTES: u32 = 128;
pub const crypto_pwhash_STRPREFIX: &'static [u8; 11usize] = b"$argon2id$\0";
pub const crypto_pwhash_OPSLIMIT_MIN: u32 = 1;
pub const crypto_pwhash_OPSLIMIT_MAX: u32 = 4294967295;
pub const crypto_pwhash_MEMLIMIT_MIN: u32 = 8192;
pub const crypto_pwhash_OPSLIMIT_INTERACTIVE: u32 = 2;
pub const crypto_pwhash_MEMLIMIT_INTERACTIVE: u32 = 67108864;
pub const crypto_pwhash_OPSLIMIT_MODERATE: u32 = 3;
pub const crypto_pwhash_MEMLIMIT_MODERATE: u32 = 268435456;
pub const crypto_pwhash_OPSLIMIT_SENSITIVE: u32 = 4;
pub const crypto_pwhash_MEMLIMIT_SENSITIVE: u32 = 1073741824;
pub const crypto_pwhash_PRIMITIVE: &'static [u8; 8usize] = b"argon2i\0";
pub const crypto_secretbox_xsalsa20poly1305_KEYBYTES: u32 = 32;
pub const crypto_secretbox_xsalsa20poly1305_NONCEBYTES: u32 = 24;
pub const crypto_secretbox_xsalsa20poly1305_MACBYTES: u32 = 16;
pub const crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES: u32 = 16;
pub const crypto_secretbox_xsalsa20poly1305_ZEROBYTES: u32 = 32;
pub const crypto_secretbox_KEYBYTES: u32 = 32;
pub const crypto_secretbox_NONCEBYTES: u32 = 24;
pub const crypto_secretbox_MACBYTES: u32 = 16;
pub const crypto_secretbox_PRIMITIVE: &'static [u8; 17usize] = b"xsalsa20poly1305\0";
pub const crypto_secretbox_ZEROBYTES: u32 = 32;
pub const crypto_secretbox_BOXZEROBYTES: u32 = 16;
pub const crypto_secretstream_xchacha20poly1305_ABYTES: u32 = 17;
pub const crypto_secretstream_xchacha20poly1305_HEADERBYTES: u32 = 24;
pub const crypto_secretstream_xchacha20poly1305_KEYBYTES: u32 = 32;
pub const crypto_secretstream_xchacha20poly1305_TAG_MESSAGE: u32 = 0;
pub const crypto_secretstream_xchacha20poly1305_TAG_PUSH: u32 = 1;
pub const crypto_secretstream_xchacha20poly1305_TAG_REKEY: u32 = 2;
pub const crypto_secretstream_xchacha20poly1305_TAG_FINAL: u32 = 3;
pub const crypto_sign_BYTES: u32 = 64;
pub const crypto_sign_PUBLICKEYBYTES: u32 = 32;
pub const crypto_sign_SECRETKEYBYTES: u32 = 64;
pub const crypto_secretbox_xchacha20poly1305_KEYBYTES: u32 = 32;
pub const crypto_secretbox_xchacha20poly1305_NONCEBYTES: u32 = 24;
pub const crypto_secretbox_xchacha20poly1305_MACBYTES: u32 = 16;
pub const crypto_pwhash_scryptsalsa208sha256_BYTES_MIN: u32 = 16;
pub const crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN: u32 = 0;
pub const crypto_pwhash_scryptsalsa208sha256_SALTBYTES: u32 = 32;
pub const crypto_pwhash_scryptsalsa208sha256_STRBYTES: u32 = 102;
pub const crypto_pwhash_scryptsalsa208sha256_STRPREFIX: &'static [u8; 4usize] = b"$7$\0";
pub const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN: u32 = 32768;
pub const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX: u32 = 4294967295;
pub const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN: u32 = 16777216;
pub const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE: u32 = 524288;
pub const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE: u32 = 16777216;
pub const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE: u32 = 33554432;
pub const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE: u32 = 1073741824;
pub type __uint32_t = ::std::os::raw::c_uint;
pub type __uint64_t = ::std::os::raw::c_ulong;
extern "C" {
    pub fn sodium_init() -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_is_available() -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_keybytes() -> usize;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_nsecbytes() -> usize;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_npubbytes() -> usize;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_abytes() -> usize;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_messagebytes_max() -> usize;
}
#[repr(C)]
#[repr(align(16))]
#[derive(Copy, Clone)]
pub struct crypto_aead_aes256gcm_state_ {
    pub opaque: [::std::os::raw::c_uchar; 512usize],
}
pub type crypto_aead_aes256gcm_state = crypto_aead_aes256gcm_state_;
extern "C" {
    pub fn crypto_aead_aes256gcm_statebytes() -> usize;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_encrypt(
        c: *mut ::std::os::raw::c_uchar,
        clen_p: *mut ::std::os::raw::c_ulonglong,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        ad: *const ::std::os::raw::c_uchar,
        adlen: ::std::os::raw::c_ulonglong,
        nsec: *const ::std::os::raw::c_uchar,
        npub: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_decrypt(
        m: *mut ::std::os::raw::c_uchar,
        mlen_p: *mut ::std::os::raw::c_ulonglong,
        nsec: *mut ::std::os::raw::c_uchar,
        c: *const ::std::os::raw::c_uchar,
        clen: ::std::os::raw::c_ulonglong,
        ad: *const ::std::os::raw::c_uchar,
        adlen: ::std::os::raw::c_ulonglong,
        npub: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_encrypt_detached(
        c: *mut ::std::os::raw::c_uchar,
        mac: *mut ::std::os::raw::c_uchar,
        maclen_p: *mut ::std::os::raw::c_ulonglong,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        ad: *const ::std::os::raw::c_uchar,
        adlen: ::std::os::raw::c_ulonglong,
        nsec: *const ::std::os::raw::c_uchar,
        npub: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_decrypt_detached(
        m: *mut ::std::os::raw::c_uchar,
        nsec: *mut ::std::os::raw::c_uchar,
        c: *const ::std::os::raw::c_uchar,
        clen: ::std::os::raw::c_ulonglong,
        mac: *const ::std::os::raw::c_uchar,
        ad: *const ::std::os::raw::c_uchar,
        adlen: ::std::os::raw::c_ulonglong,
        npub: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_beforenm(
        ctx_: *mut crypto_aead_aes256gcm_state,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_encrypt_afternm(
        c: *mut ::std::os::raw::c_uchar,
        clen_p: *mut ::std::os::raw::c_ulonglong,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        ad: *const ::std::os::raw::c_uchar,
        adlen: ::std::os::raw::c_ulonglong,
        nsec: *const ::std::os::raw::c_uchar,
        npub: *const ::std::os::raw::c_uchar,
        ctx_: *const crypto_aead_aes256gcm_state,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_decrypt_afternm(
        m: *mut ::std::os::raw::c_uchar,
        mlen_p: *mut ::std::os::raw::c_ulonglong,
        nsec: *mut ::std::os::raw::c_uchar,
        c: *const ::std::os::raw::c_uchar,
        clen: ::std::os::raw::c_ulonglong,
        ad: *const ::std::os::raw::c_uchar,
        adlen: ::std::os::raw::c_ulonglong,
        npub: *const ::std::os::raw::c_uchar,
        ctx_: *const crypto_aead_aes256gcm_state,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_encrypt_detached_afternm(
        c: *mut ::std::os::raw::c_uchar,
        mac: *mut ::std::os::raw::c_uchar,
        maclen_p: *mut ::std::os::raw::c_ulonglong,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        ad: *const ::std::os::raw::c_uchar,
        adlen: ::std::os::raw::c_ulonglong,
        nsec: *const ::std::os::raw::c_uchar,
        npub: *const ::std::os::raw::c_uchar,
        ctx_: *const crypto_aead_aes256gcm_state,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_decrypt_detached_afternm(
        m: *mut ::std::os::raw::c_uchar,
        nsec: *mut ::std::os::raw::c_uchar,
        c: *const ::std::os::raw::c_uchar,
        clen: ::std::os::raw::c_ulonglong,
        mac: *const ::std::os::raw::c_uchar,
        ad: *const ::std::os::raw::c_uchar,
        adlen: ::std::os::raw::c_ulonglong,
        npub: *const ::std::os::raw::c_uchar,
        ctx_: *const crypto_aead_aes256gcm_state,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_aead_aes256gcm_keygen(k: *mut ::std::os::raw::c_uchar);
}
extern "C" {
    pub fn crypto_aead_xchacha20poly1305_ietf_keybytes() -> usize;
}
extern "C" {
    pub fn crypto_aead_xchacha20poly1305_ietf_nsecbytes() -> usize;
}
extern "C" {
    pub fn crypto_aead_xchacha20poly1305_ietf_npubbytes() -> usize;
}
extern "C" {
    pub fn crypto_aead_xchacha20poly1305_ietf_abytes() -> usize;
}
extern "C" {
    pub fn crypto_aead_xchacha20poly1305_ietf_messagebytes_max() -> usize;
}
extern "C" {
    pub fn crypto_aead_xchacha20poly1305_ietf_encrypt(
        c: *mut ::std::os::raw::c_uchar,
        clen_p: *mut ::std::os::raw::c_ulonglong,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        ad: *const ::std::os::raw::c_uchar,
        adlen: ::std::os::raw::c_ulonglong,
        nsec: *const ::std::os::raw::c_uchar,
        npub: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_aead_xchacha20poly1305_ietf_decrypt(
        m: *mut ::std::os::raw::c_uchar,
        mlen_p: *mut ::std::os::raw::c_ulonglong,
        nsec: *mut ::std::os::raw::c_uchar,
        c: *const ::std::os::raw::c_uchar,
        clen: ::std::os::raw::c_ulonglong,
        ad: *const ::std::os::raw::c_uchar,
        adlen: ::std::os::raw::c_ulonglong,
        npub: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        c: *mut ::std::os::raw::c_uchar,
        mac: *mut ::std::os::raw::c_uchar,
        maclen_p: *mut ::std::os::raw::c_ulonglong,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        ad: *const ::std::os::raw::c_uchar,
        adlen: ::std::os::raw::c_ulonglong,
        nsec: *const ::std::os::raw::c_uchar,
        npub: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
        m: *mut ::std::os::raw::c_uchar,
        nsec: *mut ::std::os::raw::c_uchar,
        c: *const ::std::os::raw::c_uchar,
        clen: ::std::os::raw::c_ulonglong,
        mac: *const ::std::os::raw::c_uchar,
        ad: *const ::std::os::raw::c_uchar,
        adlen: ::std::os::raw::c_ulonglong,
        npub: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_aead_xchacha20poly1305_ietf_keygen(k: *mut ::std::os::raw::c_uchar);
}
extern "C" {
    pub fn crypto_box_keypair(
        pk: *mut ::std::os::raw::c_uchar,
        sk: *mut ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_box_easy(
        c: *mut ::std::os::raw::c_uchar,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        n: *const ::std::os::raw::c_uchar,
        pk: *const ::std::os::raw::c_uchar,
        sk: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_box_open_easy(
        m: *mut ::std::os::raw::c_uchar,
        c: *const ::std::os::raw::c_uchar,
        clen: ::std::os::raw::c_ulonglong,
        n: *const ::std::os::raw::c_uchar,
        pk: *const ::std::os::raw::c_uchar,
        sk: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_box_sealbytes() -> usize;
}
extern "C" {
    pub fn crypto_box_seal(
        c: *mut ::std::os::raw::c_uchar,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        pk: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_box_seal_open(
        m: *mut ::std::os::raw::c_uchar,
        c: *const ::std::os::raw::c_uchar,
        clen: ::std::os::raw::c_ulonglong,
        pk: *const ::std::os::raw::c_uchar,
        sk: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
#[repr(C)]
#[repr(align(64))]
#[derive(Copy, Clone)]
pub struct crypto_generichash_blake2b_state {
    pub opaque: [::std::os::raw::c_uchar; 384usize],
}
pub type crypto_generichash_state = crypto_generichash_blake2b_state;
extern "C" {
    pub fn crypto_generichash_statebytes() -> usize;
}
extern "C" {
    pub fn crypto_generichash_init(
        state: *mut crypto_generichash_state,
        key: *const ::std::os::raw::c_uchar,
        keylen: usize,
        outlen: usize,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_generichash_update(
        state: *mut crypto_generichash_state,
        in_: *const ::std::os::raw::c_uchar,
        inlen: ::std::os::raw::c_ulonglong,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_generichash_final(
        state: *mut crypto_generichash_state,
        out: *mut ::std::os::raw::c_uchar,
        outlen: usize,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_kdf_derive_from_key(
        subkey: *mut ::std::os::raw::c_uchar,
        subkey_len: usize,
        subkey_id: u64,
        ctx: *const ::std::os::raw::c_char,
        key: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_kdf_keygen(k: *mut ::std::os::raw::c_uchar);
}
extern "C" {
    pub fn crypto_kx_publickeybytes() -> usize;
}
extern "C" {
    pub fn crypto_kx_secretkeybytes() -> usize;
}
extern "C" {
    pub fn crypto_kx_seedbytes() -> usize;
}
extern "C" {
    pub fn crypto_kx_sessionkeybytes() -> usize;
}
extern "C" {
    pub fn crypto_kx_primitive() -> *const ::std::os::raw::c_char;
}
extern "C" {
    pub fn crypto_kx_seed_keypair(
        pk: *mut ::std::os::raw::c_uchar,
        sk: *mut ::std::os::raw::c_uchar,
        seed: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_kx_keypair(
        pk: *mut ::std::os::raw::c_uchar,
        sk: *mut ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_kx_client_session_keys(
        rx: *mut ::std::os::raw::c_uchar,
        tx: *mut ::std::os::raw::c_uchar,
        client_pk: *const ::std::os::raw::c_uchar,
        client_sk: *const ::std::os::raw::c_uchar,
        server_pk: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_kx_server_session_keys(
        rx: *mut ::std::os::raw::c_uchar,
        tx: *mut ::std::os::raw::c_uchar,
        server_pk: *const ::std::os::raw::c_uchar,
        server_sk: *const ::std::os::raw::c_uchar,
        client_pk: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_pwhash(
        out: *mut ::std::os::raw::c_uchar,
        outlen: ::std::os::raw::c_ulonglong,
        passwd: *const ::std::os::raw::c_char,
        passwdlen: ::std::os::raw::c_ulonglong,
        salt: *const ::std::os::raw::c_uchar,
        opslimit: ::std::os::raw::c_ulonglong,
        memlimit: usize,
        alg: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_secretbox_xsalsa20poly1305_keybytes() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_xsalsa20poly1305_noncebytes() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_xsalsa20poly1305_macbytes() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_xsalsa20poly1305_messagebytes_max() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_xsalsa20poly1305(
        c: *mut ::std::os::raw::c_uchar,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        n: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_secretbox_xsalsa20poly1305_open(
        m: *mut ::std::os::raw::c_uchar,
        c: *const ::std::os::raw::c_uchar,
        clen: ::std::os::raw::c_ulonglong,
        n: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_secretbox_xsalsa20poly1305_keygen(k: *mut ::std::os::raw::c_uchar);
}
extern "C" {
    pub fn crypto_secretbox_xsalsa20poly1305_boxzerobytes() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_xsalsa20poly1305_zerobytes() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_keybytes() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_noncebytes() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_macbytes() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_primitive() -> *const ::std::os::raw::c_char;
}
extern "C" {
    pub fn crypto_secretbox_messagebytes_max() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_easy(
        c: *mut ::std::os::raw::c_uchar,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        n: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_secretbox_open_easy(
        m: *mut ::std::os::raw::c_uchar,
        c: *const ::std::os::raw::c_uchar,
        clen: ::std::os::raw::c_ulonglong,
        n: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_secretbox_detached(
        c: *mut ::std::os::raw::c_uchar,
        mac: *mut ::std::os::raw::c_uchar,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        n: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_secretbox_open_detached(
        m: *mut ::std::os::raw::c_uchar,
        c: *const ::std::os::raw::c_uchar,
        mac: *const ::std::os::raw::c_uchar,
        clen: ::std::os::raw::c_ulonglong,
        n: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_secretbox_keygen(k: *mut ::std::os::raw::c_uchar);
}
extern "C" {
    pub fn crypto_secretbox_zerobytes() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_boxzerobytes() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_open(
        m: *mut ::std::os::raw::c_uchar,
        c: *const ::std::os::raw::c_uchar,
        clen: ::std::os::raw::c_ulonglong,
        n: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_abytes() -> usize;
}
extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_headerbytes() -> usize;
}
extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_keybytes() -> usize;
}
extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_messagebytes_max() -> usize;
}
extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_tag_message() -> ::std::os::raw::c_uchar;
}
extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_tag_push() -> ::std::os::raw::c_uchar;
}
extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_tag_rekey() -> ::std::os::raw::c_uchar;
}
extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_tag_final() -> ::std::os::raw::c_uchar;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct crypto_secretstream_xchacha20poly1305_state {
    pub k: [::std::os::raw::c_uchar; 32usize],
    pub nonce: [::std::os::raw::c_uchar; 12usize],
    pub _pad: [::std::os::raw::c_uchar; 8usize],
}
extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_statebytes() -> usize;
}
extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_keygen(k: *mut ::std::os::raw::c_uchar);
}
extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_init_push(
        state: *mut crypto_secretstream_xchacha20poly1305_state,
        header: *mut ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_push(
        state: *mut crypto_secretstream_xchacha20poly1305_state,
        c: *mut ::std::os::raw::c_uchar,
        clen_p: *mut ::std::os::raw::c_ulonglong,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        ad: *const ::std::os::raw::c_uchar,
        adlen: ::std::os::raw::c_ulonglong,
        tag: ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_init_pull(
        state: *mut crypto_secretstream_xchacha20poly1305_state,
        header: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_pull(
        state: *mut crypto_secretstream_xchacha20poly1305_state,
        m: *mut ::std::os::raw::c_uchar,
        mlen_p: *mut ::std::os::raw::c_ulonglong,
        tag_p: *mut ::std::os::raw::c_uchar,
        c: *const ::std::os::raw::c_uchar,
        clen: ::std::os::raw::c_ulonglong,
        ad: *const ::std::os::raw::c_uchar,
        adlen: ::std::os::raw::c_ulonglong,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_rekey(
        state: *mut crypto_secretstream_xchacha20poly1305_state,
    );
}
extern "C" {
    pub fn crypto_sign_keypair(
        pk: *mut ::std::os::raw::c_uchar,
        sk: *mut ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_sign(
        sm: *mut ::std::os::raw::c_uchar,
        smlen_p: *mut ::std::os::raw::c_ulonglong,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        sk: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_sign_open(
        m: *mut ::std::os::raw::c_uchar,
        mlen_p: *mut ::std::os::raw::c_ulonglong,
        sm: *const ::std::os::raw::c_uchar,
        smlen: ::std::os::raw::c_ulonglong,
        pk: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_sign_detached(
        sig: *mut ::std::os::raw::c_uchar,
        siglen_p: *mut ::std::os::raw::c_ulonglong,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        sk: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_sign_verify_detached(
        sig: *const ::std::os::raw::c_uchar,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        pk: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn randombytes_buf(buf: *mut ::std::os::raw::c_void, size: usize);
}
extern "C" {
    pub fn randombytes_buf_deterministic(
        buf: *mut ::std::os::raw::c_void,
        size: usize,
        seed: *const ::std::os::raw::c_uchar,
    );
}
extern "C" {
    pub fn randombytes_random() -> u32;
}
extern "C" {
    pub fn randombytes_uniform(upper_bound: u32) -> u32;
}
extern "C" {
    pub fn sodium_increment(n: *mut ::std::os::raw::c_uchar, nlen: usize);
}
extern "C" {
    pub fn sodium_bin2hex(
        hex: *mut ::std::os::raw::c_char,
        hex_maxlen: usize,
        bin: *const ::std::os::raw::c_uchar,
        bin_len: usize,
    ) -> *mut ::std::os::raw::c_char;
}
extern "C" {
    pub fn crypto_secretbox_xchacha20poly1305_keybytes() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_xchacha20poly1305_noncebytes() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_xchacha20poly1305_macbytes() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_xchacha20poly1305_messagebytes_max() -> usize;
}
extern "C" {
    pub fn crypto_secretbox_xchacha20poly1305_easy(
        c: *mut ::std::os::raw::c_uchar,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        n: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_secretbox_xchacha20poly1305_open_easy(
        m: *mut ::std::os::raw::c_uchar,
        c: *const ::std::os::raw::c_uchar,
        clen: ::std::os::raw::c_ulonglong,
        n: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_secretbox_xchacha20poly1305_detached(
        c: *mut ::std::os::raw::c_uchar,
        mac: *mut ::std::os::raw::c_uchar,
        m: *const ::std::os::raw::c_uchar,
        mlen: ::std::os::raw::c_ulonglong,
        n: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn crypto_secretbox_xchacha20poly1305_open_detached(
        m: *mut ::std::os::raw::c_uchar,
        c: *const ::std::os::raw::c_uchar,
        mac: *const ::std::os::raw::c_uchar,
        clen: ::std::os::raw::c_ulonglong,
        n: *const ::std::os::raw::c_uchar,
        k: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
pub const crypto_generichash_STATEBYTES: usize = 384;
