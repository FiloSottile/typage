import { describe, it, assert, expect } from "vitest"
import { plaintextSize, ciphertextSize } from "../lib/stream.js"

describe("stream", function () {
    it.for([
        0, 1, 15, 16, 17, 500,
        64 * 1024 - 1, 64 * 1024, 64 * 1024 + 1,
        64 * 1024 * 2 - 1, 64 * 1024 * 2, 64 * 1024 * 2 + 1
    ])("should round-trip plaintext size and ciphertext size", function (ps) {
        assert.equal(ps, plaintextSize(ciphertextSize(ps)),
            `plaintextSize(ciphertextSize(${ps})) should return ${ps}`)
    })
    it.for([
        0, 1, 15,
        64 * 1024 + 16 + 1, 64 * 1024 + 16 + 15,
        64 * 1024 * 2 + 16 * 2 + 1, 64 * 1024 * 2 + 16 * 2 + 15,
    ])("should throw for invalid chiphertext size", function (cs) {
        expect(() => plaintextSize(cs)).to.throw()
    })
})
