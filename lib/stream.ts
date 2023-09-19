import _sodium from "libsodium-wrappers-sumo"

const sodium = _sodium

// We can't use sodium.crypto_aead_chacha20poly1305_IETF_ABYTES here before
// sodium.ready, or it will make the constant be silently NaN, and nothing will
// throw but plaintext will end up empty. Love it.
const chacha20poly1305Overhead = 16

const chunkSize = 64 * 1024
const chunkSizeWithOverhead = chunkSize + chacha20poly1305Overhead

export function decryptSTREAM(key: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    const streamNonce = new Uint8Array(12)
    const incNonce = () => {
        for (let i = streamNonce.length - 2; i >= 0; i--) {
            streamNonce[i]++
            if (streamNonce[i] !== 0) break
        }
    }

    const chunkCount = Math.ceil(ciphertext.length / chunkSizeWithOverhead)
    const overhead = chunkCount * chacha20poly1305Overhead
    const plaintext = new Uint8Array(ciphertext.length - overhead)

    let plaintextSlice = plaintext
    while (ciphertext.length > chunkSizeWithOverhead) {
        const chunk = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
            null, ciphertext.subarray(0, chunkSizeWithOverhead), null, streamNonce, key)
        plaintextSlice.set(chunk)
        plaintextSlice = plaintextSlice.subarray(chunk.length)
        ciphertext = ciphertext.subarray(chunkSizeWithOverhead)
        incNonce()
    }

    streamNonce[11] = 1 // Last chunk flag.
    const chunk = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, ciphertext, null, streamNonce, key)
    plaintextSlice.set(chunk)
    if (chunk.length === 0 && plaintext.length !== 0)
        throw Error("empty final chunk")
    if (plaintextSlice.length !== chunk.length)
        throw Error("stream: internal error: didn't fill expected plaintext buffer")

    return plaintext
}

export function encryptSTREAM(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
    const streamNonce = new Uint8Array(12)
    const incNonce = () => {
        for (let i = streamNonce.length - 2; i >= 0; i--) {
            streamNonce[i]++
            if (streamNonce[i] !== 0) break
        }
    }

    const chunkCount = plaintext.length === 0 ? 1 : Math.ceil(plaintext.length / chunkSize)
    const overhead = chunkCount * chacha20poly1305Overhead
    const ciphertext = new Uint8Array(plaintext.length + overhead)

    let ciphertextSlice = ciphertext
    while (plaintext.length > chunkSize) {
        const chunk = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
            plaintext.subarray(0, chunkSize), null, null, streamNonce, key)
        ciphertextSlice.set(chunk)
        ciphertextSlice = ciphertextSlice.subarray(chunk.length)
        plaintext = plaintext.subarray(chunkSize)
        incNonce()
    }

    streamNonce[11] = 1 // Last chunk flag.
    const chunk = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(plaintext, null, null, streamNonce, key)
    ciphertextSlice.set(chunk)
    if (ciphertextSlice.length !== chunk.length)
        throw Error("stream: internal error: didn't fill expected ciphertext buffer")

    return ciphertext
}
