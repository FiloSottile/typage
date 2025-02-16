import { chacha20poly1305 } from "@noble/ciphers/chacha"

const chacha20poly1305Overhead = 16

export const chunkSize = /* @__PURE__ */ (() => 64 * 1024)()
const chunkSizeWithOverhead = /* @__PURE__ */ (() => chunkSize + chacha20poly1305Overhead)()

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
        const chunk = chacha20poly1305(key, streamNonce).decrypt(
            ciphertext.subarray(0, chunkSizeWithOverhead))
        plaintextSlice.set(chunk)
        plaintextSlice = plaintextSlice.subarray(chunk.length)
        ciphertext = ciphertext.subarray(chunkSizeWithOverhead)
        incNonce()
    }

    streamNonce[11] = 1 // Last chunk flag.
    const chunk = chacha20poly1305(key, streamNonce).decrypt(ciphertext)
    plaintextSlice.set(chunk)
    if (chunk.length === 0 && plaintext.length !== 0) {
        throw Error("empty final chunk")
    }
    if (plaintextSlice.length !== chunk.length) {
        throw Error("stream: internal error: didn't fill expected plaintext buffer")
    }

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
        const chunk = chacha20poly1305(key, streamNonce).encrypt(
            plaintext.subarray(0, chunkSize))
        ciphertextSlice.set(chunk)
        ciphertextSlice = ciphertextSlice.subarray(chunk.length)
        plaintext = plaintext.subarray(chunkSize)
        incNonce()
    }

    streamNonce[11] = 1 // Last chunk flag.
    const chunk = chacha20poly1305(key, streamNonce).encrypt(plaintext)
    ciphertextSlice.set(chunk)
    if (ciphertextSlice.length !== chunk.length) {
        throw Error("stream: internal error: didn't fill expected ciphertext buffer")
    }

    return ciphertext
}
