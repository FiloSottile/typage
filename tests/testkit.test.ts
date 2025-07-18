import { describe, it, assert, expect, onTestFinished } from "vitest"
import { encodeHeader, encodeHeaderNoMAC, parseHeader } from "../lib/format.js"
import { decryptSTREAM, encryptSTREAM } from "../lib/stream.js"
import { stream, readAll } from "../lib/io.js"
import { forceWebCryptoOff } from "../lib/x25519.js"
import { hkdf } from "@noble/hashes/hkdf"
import { sha256 } from "@noble/hashes/sha2"
import { hex } from "@scure/base"
import { Decrypter, armor } from "../lib/index.js"
import * as testkit from "cctv-age"

const itSlowly = typeof process !== "undefined" && process.env.SLOW ? it : it.skip

describe("CCTV testkit", async function () {
    interface Vector {
        name: string,
        meta: Record<string, string>,
        body: Uint8Array,
    }
    const vectors: Vector[] = []
    for (const [name, contents] of Object.entries(testkit)) {
        const sepIdx = findSeparator(contents)
        const header = new TextDecoder().decode(contents.subarray(0, sepIdx))
        const body = contents.subarray(sepIdx + 2)
        const vector: Vector = { name: name, meta: {}, body: body }
        for (const line of header.split("\n")) {
            const parts = line.split(": ", 2)
            vector.meta[parts[0]] = parts[1]
        }
        if (!vector.meta.expect) {
            throw Error("no metadata found in " + name)
        }
        if (vector.meta.compressed === "zlib") {
            vector.body = new Uint8Array(await new Response(
                new Blob([vector.body]).stream().pipeThrough(new DecompressionStream("deflate"))
            ).arrayBuffer())
        } else if (vector.meta.compressed) {
            throw Error("unknown compression: " + vector.meta.compressed)
        }
        vectors.push(vector)
    }

    for (const vec of vectors) {
        describe(vec.name, async function () {
            const itSlowlyIfBig = vec.body.length > 1024 * 1024 ? it.skip : vec.body.length > 1024 ? itSlowly : it
            const body = () => vec.meta.armored ? armor.decode(new TextDecoder().decode(vec.body)) : vec.body
            if (vec.meta.expect === "success") {
                it("should succeed", async function () {
                    const d = new Decrypter()
                    if (vec.meta.passphrase) d.addPassphrase(vec.meta.passphrase)
                    if (vec.meta.identity) d.addIdentity(vec.meta.identity)
                    const plaintext = await d.decrypt(body())
                    assert.equal(hex.encode(sha256(plaintext)), vec.meta.payload)
                })
                it("should succeed via streaming", async function () {
                    const d = new Decrypter()
                    if (vec.meta.passphrase) d.addPassphrase(vec.meta.passphrase)
                    if (vec.meta.identity) d.addIdentity(vec.meta.identity)
                    const plaintext = await readAll(await d.decrypt(stream(body())))
                    assert.equal(hex.encode(sha256(plaintext)), vec.meta.payload)
                })
                itSlowlyIfBig("should succeed via streaming byte-by-byte", async function () {
                    const d = new Decrypter()
                    if (vec.meta.passphrase) d.addPassphrase(vec.meta.passphrase)
                    if (vec.meta.identity) d.addIdentity(vec.meta.identity)
                    const source = streamByteByByte(body())
                    const plaintext = await readAll(await d.decrypt(source))
                    assert.equal(hex.encode(sha256(plaintext)), vec.meta.payload)
                })
                if (vec.meta.identity) {
                    it("should succeed without Web Crypto", async function () {
                        withoutWebCrypto()
                        const d = new Decrypter()
                        d.addIdentity(vec.meta.identity)
                        const plaintext = await d.decrypt(body())
                        assert.equal(hex.encode(sha256(plaintext)), vec.meta.payload)
                    })
                }
                if (vec.meta.armored) {
                    it("should round-trip armor", function () {
                        const normalize = (s: string) => s.replaceAll("\r\n", "\n").trim()
                        assert.deepEqual(normalize(armor.encode(body())),
                            normalize(new TextDecoder().decode(vec.body)))
                    })
                }
                const h = await parseHeader(stream(body()))
                const rest = await readAll(h.rest)
                const nonce = rest.subarray(0, 16)
                const payload = rest.subarray(16)
                it("should round-trip header encoding", function () {
                    assert.deepEqual(encodeHeaderNoMAC(h.stanzas), h.headerNoMAC)
                    const hh = encodeHeader(h.stanzas, h.MAC)
                    const got = new Uint8Array(hh.length + rest.length)
                    got.set(hh)
                    got.set(rest, hh.length)
                    assert.deepEqual(got, body())
                })
                it("should round-trip STREAM encryption", async function () {
                    const streamKey = hkdf(sha256, hex.decode(vec.meta["file key"]), nonce, "payload", 32)
                    const decrypter = decryptSTREAM(streamKey)
                    const encrypter = encryptSTREAM(streamKey)
                    const got = await readAll(stream(payload).pipeThrough(decrypter).pipeThrough(encrypter))
                    assert.deepEqual(got, payload)
                })
                itSlowlyIfBig("should round-trip STREAM encryption byte-by-byte", async function () {
                    const streamKey = hkdf(sha256, hex.decode(vec.meta["file key"]), nonce, "payload", 32)
                    const decrypter = decryptSTREAM(streamKey)
                    const encrypter = encryptSTREAM(streamKey)
                    const source = streamByteByByte(payload)
                    const got = await readAll(source.pipeThrough(decrypter).pipeThrough(encrypter))
                    assert.deepEqual(got, payload)
                })
            } else {
                it("should fail", async function () {
                    const d = new Decrypter()
                    if (vec.meta.passphrase) d.addPassphrase(vec.meta.passphrase)
                    if (vec.meta.identity) d.addIdentity(vec.meta.identity)
                    await expect(async () => await d.decrypt(body())).rejects.toThrow()
                })
                it("should fail via streaming", async function () {
                    const d = new Decrypter()
                    if (vec.meta.passphrase) d.addPassphrase(vec.meta.passphrase)
                    if (vec.meta.identity) d.addIdentity(vec.meta.identity)
                    await expect(async () => await readAll(await d.decrypt(stream(body())))).rejects.toThrow()
                })
                itSlowlyIfBig("should fail via streaming byte-by-byte", async function () {
                    const d = new Decrypter()
                    if (vec.meta.passphrase) d.addPassphrase(vec.meta.passphrase)
                    if (vec.meta.identity) d.addIdentity(vec.meta.identity)
                    await expect(async () => await readAll(await d.decrypt(streamByteByByte(body())))).rejects.toThrow()
                })
                if (vec.meta.identity) {
                    it("should fail without Web Crypto", async function () {
                        withoutWebCrypto()
                        const d = new Decrypter()
                        d.addIdentity(vec.meta.identity)
                        await expect(async () => await d.decrypt(body())).rejects.toThrow()
                    })
                }
            }
        })
    }
})

function withoutWebCrypto() {
    forceWebCryptoOff(true)
    onTestFinished(() => { forceWebCryptoOff(false) })
}

function streamByteByByte(a: Uint8Array): ReadableStream<Uint8Array> {
    return new ReadableStream<Uint8Array>({
        start(controller) {
            for (const b of a) {
                controller.enqueue(new Uint8Array([b]))
            }
            controller.close()
        }
    })
}

function findSeparator(data: Uint8Array): number {
    for (let i = 0; i < data.length; i++) {
        if (data[i] === 0x0A && data[i + 1] === 0x0A) {
            return i
        }
    }
    throw Error("no separator found")
}
