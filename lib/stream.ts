import * as sodium from "libsodium-wrappers-sumo"

export function decryptSTREAM(key: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    // These constants must be defined inside the function, so that happens
    // after sodium.ready, or chunkSizeWithOverhead will silently be NaN, and
    // nothing will throw but plaintext will end up empty. Love it.
    const chunkSize = 64 * 1024
    const chunkSizeWithOverhead = chunkSize + sodium.crypto_aead_chacha20poly1305_IETF_ABYTES

    const streamNonce = new Uint8Array(12)
    const incNonce = () => {
        for (let i = streamNonce.length - 2; i >= 0; i--) {
            streamNonce[i]++
            if (streamNonce[i] != 0) break
        }
    }

    const overhead = Math.ceil(ciphertext.length / chunkSizeWithOverhead) *
        sodium.crypto_aead_chacha20poly1305_IETF_ABYTES
    const plaintext = new Uint8Array(ciphertext.length - overhead)

    let plaintextSlice = plaintext
    while (ciphertext.length > chunkSizeWithOverhead) {
        const chunk = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
            null, ciphertext.subarray(0, chunkSizeWithOverhead), null, streamNonce, key)
        plaintextSlice.set(chunk)
        plaintextSlice = plaintextSlice.subarray(chunkSize)
        ciphertext = ciphertext.subarray(chunkSizeWithOverhead)
        incNonce()
    }

    streamNonce[11] = 1 // Last chunk flag.
    const chunk = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, ciphertext, null, streamNonce, key)
    plaintextSlice.set(chunk)
    if (plaintextSlice.length != chunk.length)
        throw Error("stream: internal error: didn't fill expected plaintext buffer")

    return plaintext
}
