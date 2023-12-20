import { describe, it, assert } from "vitest"
import { decodeBase64, encodeHeader, encodeHeaderNoMAC, parseHeader } from "../lib/format.js"

const to_string = (a: Uint8Array): string => new TextDecoder().decode(a)
const from_string = (s: string): Uint8Array => new TextEncoder().encode(s)

const exampleHeader = `age-encryption.org/v1
-> X25519 abc
0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM
this is the payload`

describe("parseHeader", () => {
    it("should parse a well formatted header", () => {
        const h = parseHeader(from_string(exampleHeader))
        assert.equal(h.recipients.length, 1)
        assert.deepEqual(h.recipients[0].args, ["X25519", "abc"])
        assert.deepEqual(h.recipients[0].body, decodeBase64("0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE"))
        assert.deepEqual(h.MAC, decodeBase64("gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM"))
        assert.deepEqual(h.rest, from_string("this is the payload"))
    })
    it("should reencode to the original header", () => {
        const h = parseHeader(from_string(exampleHeader))
        assert.deepEqual(encodeHeaderNoMAC(h.recipients), h.headerNoMAC)
        const got = to_string(encodeHeader(h.recipients, h.MAC)) + to_string(h.rest)
        assert.deepEqual(got, exampleHeader)
    })
})

describe("decodeBase64", () => {
    it("should parse a valid base64 string", () => {
        assert.deepEqual(decodeBase64("dGVzdA"), from_string("test"))
    })
    it("should parse a valid base64 string with spare bits", () => {
        assert.deepEqual(decodeBase64("dGVzdDI"), from_string("test2"))
    })
    it("should reject a non-canonical base64 string", () => {
        assert.throws(() => { decodeBase64("dGVzdDJ") })
    })
    it("should reject a base64 string with padding", () => {
        assert.throws(() => { decodeBase64("dGVzdDI=") })
    })
})
