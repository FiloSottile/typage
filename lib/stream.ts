import * as sodium from "libsodium-wrappers-sumo"

const chunkSize = 64 * 1024

export function decryptSTREAM(key: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    let chunkNumber = 0
    const streamNonce = new Uint8Array(12)
    const incNonce = () => {
        chunkNumber++
        for (let i = streamNonce.length - 2; i >= 0; i--) {
            streamNonce[i]++
            if (streamNonce[i] != 0) break
        }
    }

    const overhead = Math.ceil(ciphertext.length / chunkSize) *
        sodium.crypto_aead_chacha20poly1305_IETF_ABYTES
    const plaintext = new Uint8Array(ciphertext.length - overhead)

    let rest = ciphertext
    while (rest.length > chunkSize) {
        const chunk = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
            null, rest.subarray(0, chunkSize), null, streamNonce, key)
        plaintext.set(chunk, chunkNumber * chunkSize)

        rest = rest.subarray(chunkSize)
        incNonce()
    }

    streamNonce[11] = 1 // Last chunk flag.
    const chunk = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, rest, null, streamNonce, key)
    plaintext.set(chunk, chunkNumber * chunkSize)

    if (chunkNumber * chunkSize + chunk.length != plaintext.length)
        throw Error("stream: internal error: didn't fill expected plaintext buffer")

    return plaintext
}
