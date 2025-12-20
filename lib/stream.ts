import { chacha20poly1305 } from "@noble/ciphers/chacha.js"

const chacha20poly1305Overhead = 16

const chunkSize = /* @__PURE__ */ (() => 64 * 1024)()
const chunkSizeWithOverhead = /* @__PURE__ */ (() => chunkSize + chacha20poly1305Overhead)()

export function decryptSTREAM(key: Uint8Array): TransformStream<Uint8Array, Uint8Array> {
    const streamNonce = new Uint8Array(12)
    const incNonce = () => {
        for (let i = streamNonce.length - 2; i >= 0; i--) {
            streamNonce[i]++
            if (streamNonce[i] !== 0) break
        }
    }
    let firstChunk = true

    const ciphertextBuffer = new Uint8Array(chunkSizeWithOverhead)
    let ciphertextBufferUsed = 0

    return new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
            while (chunk.length > 0) {
                if (ciphertextBufferUsed === ciphertextBuffer.length) {
                    const decryptedChunk = chacha20poly1305(key, streamNonce)
                        .decrypt(ciphertextBuffer)
                    controller.enqueue(decryptedChunk)
                    incNonce()
                    ciphertextBufferUsed = 0
                    firstChunk = false
                }
                const n = Math.min(ciphertextBuffer.length - ciphertextBufferUsed, chunk.length)
                ciphertextBuffer.set(chunk.subarray(0, n), ciphertextBufferUsed)
                ciphertextBufferUsed += n
                chunk = chunk.subarray(n)
            }
        },
        flush(controller) {
            streamNonce[11] = 1 // Last chunk flag.
            const decryptedChunk = chacha20poly1305(key, streamNonce)
                .decrypt(ciphertextBuffer.subarray(0, ciphertextBufferUsed))
            if (!firstChunk && decryptedChunk.length === 0) {
                // The final chunk can only be empty if it's the first one.
                throw new Error("final chunk is empty")
            }
            controller.enqueue(decryptedChunk)
        },
    })
}

export function plaintextSize(ciphertextSize: number): number {
    if (ciphertextSize < chacha20poly1305Overhead) {
        throw Error("ciphertext is too small")
    }
    if (ciphertextSize === chacha20poly1305Overhead) {
        return 0 // Empty plaintext.
    }
    const fullChunks = Math.floor(ciphertextSize / chunkSizeWithOverhead)
    const lastChunk = ciphertextSize % chunkSizeWithOverhead
    if (0 < lastChunk && lastChunk <= chacha20poly1305Overhead) {
        throw Error("ciphertext size is invalid")
    }
    let size = ciphertextSize
    size -= fullChunks * chacha20poly1305Overhead
    size -= lastChunk > 0 ? chacha20poly1305Overhead : 0
    return size
}

export function encryptSTREAM(key: Uint8Array): TransformStream<Uint8Array, Uint8Array> {
    const streamNonce = new Uint8Array(12)
    const incNonce = () => {
        for (let i = streamNonce.length - 2; i >= 0; i--) {
            streamNonce[i]++
            if (streamNonce[i] !== 0) break
        }
    }

    const plaintextBuffer = new Uint8Array(chunkSize)
    let plaintextBufferUsed = 0

    return new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
            while (chunk.length > 0) {
                if (plaintextBufferUsed === plaintextBuffer.length) {
                    const encryptedChunk = chacha20poly1305(key, streamNonce)
                        .encrypt(plaintextBuffer)
                    controller.enqueue(encryptedChunk)
                    incNonce()
                    plaintextBufferUsed = 0
                }
                const n = Math.min(plaintextBuffer.length - plaintextBufferUsed, chunk.length)
                plaintextBuffer.set(chunk.subarray(0, n), plaintextBufferUsed)
                plaintextBufferUsed += n
                chunk = chunk.subarray(n)
            }
        },
        flush(controller) {
            streamNonce[11] = 1 // Last chunk flag.
            const encryptedChunk = chacha20poly1305(key, streamNonce)
                .encrypt(plaintextBuffer.subarray(0, plaintextBufferUsed))
            controller.enqueue(encryptedChunk)
        },
    })
}

export function ciphertextSize(plaintextSize: number): number {
    const chunks = Math.max(1, Math.ceil(plaintextSize / chunkSize))
    return plaintextSize + chacha20poly1305Overhead * chunks
}
