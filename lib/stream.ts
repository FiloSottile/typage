import { chacha20poly1305 } from "@noble/ciphers/chacha"

const chacha20poly1305Overhead = 16

const chunkSize = /* @__PURE__ */ (() => 64 * 1024)()
const chunkSizeWithOverhead = /* @__PURE__ */ (() => chunkSize + chacha20poly1305Overhead)()

export function calculateCiphertextLength(plaintextLength: number): number {
    const chunkCount = plaintextLength === 0 ? 1 : Math.ceil(plaintextLength / chunkSize)
    const overhead = chunkCount * chacha20poly1305Overhead
    return plaintextLength + overhead
}

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

    const ciphertext = new Uint8Array(calculateCiphertextLength(plaintext.length))

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

export function decryptTransformSTREAM(ciphertextLength: number, getStreamKey: (chunk: Uint8Array) => Promise<{key: Uint8Array, payload: Uint8Array }>): TransformStream<Uint8Array, Uint8Array> {
    const streamNonce = new Uint8Array(12)
    const incNonce = () => {
        for (let i = streamNonce.length - 2; i >= 0; i--) {
            streamNonce[i]++
            if (streamNonce[i] !== 0) break
        }
    }

    const ciphertextBuffer = new Uint8Array(chunkSizeWithOverhead)
    const lastChunkSize = ciphertextLength % chunkSizeWithOverhead
    let bufferUsed = 0
    let isFirstChunk = true
    let streamKey: Uint8Array

    return new TransformStream<Uint8Array, Uint8Array>({
        async transform(chunk, controller) {
            if (isFirstChunk) {
                const { key, payload } = await getStreamKey(chunk)
                streamKey = key
                chunk = payload
                isFirstChunk = false
            }
            let chunkOffset = 0
            while (chunkOffset < chunk.length) {
                const bytesAvailable = ciphertextBuffer.length - bufferUsed
                const bytesToCopy = Math.min(bytesAvailable, chunk.length - chunkOffset)
                ciphertextBuffer.set(chunk.subarray(chunkOffset, chunkOffset + bytesToCopy), bufferUsed)
                bufferUsed += bytesToCopy
                chunkOffset += bytesToCopy
                if (bufferUsed === ciphertextBuffer.length) {
                    if (lastChunkSize === 0) {
                        streamNonce[11] = 1 // Last chunk flag in rare cases where plaintextLength % chunkSizeWithOverhead == 0
                    }
                    const decryptedChunk = chacha20poly1305(streamKey, streamNonce).decrypt(ciphertextBuffer)
                    controller.enqueue(decryptedChunk)
                    incNonce()
                    bufferUsed = 0
                }
            }
        },
        flush(controller) {
            if (bufferUsed > 0) {
                streamNonce[11] = 1 // Last chunk flag.
                const decryptedChunk = chacha20poly1305(streamKey, streamNonce).decrypt(ciphertextBuffer.subarray(0, bufferUsed))
                controller.enqueue(decryptedChunk)
            }
        },
    })

}

export function encryptTransformSTREAM(key: Uint8Array, plaintextLength: number, headerAndNonce: Uint8Array): TransformStream<Uint8Array, Uint8Array> {
    const streamNonce = new Uint8Array(12)
    const incNonce = () => {
        for (let i = streamNonce.length - 2; i >= 0; i--) {
            streamNonce[i]++
            if (streamNonce[i] !== 0) break
        }
    }

    const plaintextBuffer = new Uint8Array(chunkSize)
    const lastChunkSize = plaintextLength % chunkSize
    let bufferUsed = 0

    const ciphertextStream = new TransformStream<Uint8Array, Uint8Array>({
        start(controller) {
            controller.enqueue(headerAndNonce)
        },
        transform(chunk, controller) {
            let chunkOffset = 0
            while (chunkOffset < chunk.length) {
                const bytesAvailable = plaintextBuffer.length - bufferUsed
                const bytesToCopy = Math.min(bytesAvailable, chunk.length - chunkOffset)
                plaintextBuffer.set(chunk.subarray(chunkOffset, chunkOffset + bytesToCopy), bufferUsed)
                bufferUsed += bytesToCopy
                chunkOffset += bytesToCopy
                if (bufferUsed === plaintextBuffer.length) {
                    if (lastChunkSize === 0) {
                        streamNonce[11] = 1 // Last chunk flag in rare cases where plaintextLength % chunkSizeWithOverhead == 0
                    }
                    const encryptedChunk = chacha20poly1305(key, streamNonce).encrypt(plaintextBuffer)
                    controller.enqueue(encryptedChunk)
                    incNonce()
                    bufferUsed = 0
                }
            }
        },
        flush(controller) {
            if (bufferUsed > 0) {
                streamNonce[11] = 1 // Last chunk flag.
                const encryptedChunk = chacha20poly1305(key, streamNonce).encrypt(plaintextBuffer.subarray(0, bufferUsed))
                controller.enqueue(encryptedChunk)
            }
        },
    })

    return ciphertextStream
}
