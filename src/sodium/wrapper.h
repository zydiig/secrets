#include <sodium.h>
const size_t crypto_generichash_STATEBYTES = sizeof(crypto_generichash_state);
#include <stdint.h>

/**
 * <div rustbindgen replaces="crypto_secretstream_xchacha20poly1305_state"></div>
 */
struct OpaqueStreamState {
    uint8_t _internal[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
};