import { describe, it, assert } from "vitest"
import { base64nopad } from "@scure/base"
import { encodeHeader, encodeHeaderNoMAC, parseHeader } from "../lib/format.js"
import { stream, readAll } from "../lib/io.js"

const to_string = (a: Uint8Array): string => new TextDecoder().decode(a)
const from_string = (s: string): Uint8Array => new TextEncoder().encode(s)

const exampleHeader = `age-encryption.org/v1
-> X25519 abc
0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM
this is the payload`

describe("parseHeader", () => {
    it("should parse a well formatted header", async () => {
        const h = await parseHeader(stream(from_string(exampleHeader)))
        assert.equal(h.stanzas.length, 1)
        assert.deepEqual(h.stanzas[0].args, ["X25519", "abc"])
        assert.deepEqual(h.stanzas[0].body, base64nopad.decode("0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE"))
        assert.deepEqual(h.MAC, base64nopad.decode("gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM"))
        assert.deepEqual(await readAll(h.rest), from_string("this is the payload"))
    })
    it("should reencode to the original header", async () => {
        const h = await parseHeader(stream(from_string(exampleHeader)))
        assert.deepEqual(encodeHeaderNoMAC(h.stanzas), h.headerNoMAC)
        const got = to_string(encodeHeader(h.stanzas, h.MAC)) + to_string(await readAll(h.rest))
        assert.deepEqual(got, exampleHeader)
    })
})

describe("base64nopad.decode", () => {
    it("should parse a valid base64 string", () => {
        assert.deepEqual(base64nopad.decode("dGVzdA"), from_string("test"))
    })
    it("should parse a valid base64 string with spare bits", () => {
        assert.deepEqual(base64nopad.decode("dGVzdDI"), from_string("test2"))
    })
    it("should reject a non-canonical base64 string", () => {
        assert.throws(() => { base64nopad.decode("dGVzdDJ") })
    })
    it("should reject a base64 string with padding", () => {
        assert.throws(() => { base64nopad.decode("dGVzdDI=") })
    })
})
