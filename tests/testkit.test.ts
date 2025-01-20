import { describe, it, assert, expect, onTestFinished } from "vitest"
import { encodeHeader, encodeHeaderNoMAC, parseHeader } from "../lib/format.js"
import { decryptSTREAM, encryptSTREAM } from "../lib/stream.js"
import { forceWebCryptoOff } from "../lib/x25519.js"
import { hkdf } from "@noble/hashes/hkdf"
import { sha256 } from "@noble/hashes/sha256"
import { hex } from "@scure/base"
import { Decrypter, armor } from "../lib/index.js"
import * as testkit from "cctv-age"

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
        let body = () => vec.body
        if (vec.meta.armored) {
            body = () => armor.decode(new TextDecoder().decode(vec.body))
        }
        if (vec.meta.expect === "success") {
            it(vec.name + " should succeed", async function () {
                const d = new Decrypter()
                if (vec.meta.passphrase) d.addPassphrase(vec.meta.passphrase)
                if (vec.meta.identity) d.addIdentity(vec.meta.identity)
                const plaintext = await d.decrypt(body())
                assert.equal(hex.encode(sha256(plaintext)), vec.meta.payload)
            })
            if (vec.meta.identity) {
                it(vec.name + " should succeed without Web Crypto", async function () {
                    withoutWebCrypto()
                    const d = new Decrypter()
                    d.addIdentity(vec.meta.identity)
                    const plaintext = await d.decrypt(body())
                    assert.equal(hex.encode(sha256(plaintext)), vec.meta.payload)
                })
            }
            if (vec.meta.armored) {
                it(vec.name + " should round-trip armor", function () {
                    const normalize = (s: string) => s.replaceAll("\r\n", "\n").trim()
                    assert.deepEqual(normalize(armor.encode(body())),
                        normalize(new TextDecoder().decode(vec.body)))
                })
            }
            it(vec.name + " should round-trip header encoding", function () {
                const h = parseHeader(body())
                assert.deepEqual(encodeHeaderNoMAC(h.stanzas), h.headerNoMAC)
                const hh = encodeHeader(h.stanzas, h.MAC)
                const got = new Uint8Array(hh.length + h.rest.length)
                got.set(hh)
                got.set(h.rest, hh.length)
                assert.deepEqual(got, body())
            })
            it(vec.name + " should round-trip STREAM encryption", function () {
                const h = parseHeader(body())
                const nonce = h.rest.subarray(0, 16)
                const streamKey = hkdf(sha256, hex.decode(vec.meta["file key"]), nonce, "payload", 32)
                const payload = h.rest.subarray(16)
                const plaintext = decryptSTREAM(streamKey, payload)
                assert.deepEqual(encryptSTREAM(streamKey, plaintext), payload)
            })
        } else {
            it(vec.name + " should fail", async function () {
                const d = new Decrypter()
                if (vec.meta.passphrase) d.addPassphrase(vec.meta.passphrase)
                if (vec.meta.identity) d.addIdentity(vec.meta.identity)
                await expect(async () => await d.decrypt(body())).rejects.toThrow()
            })
            if (vec.meta.identity) {
                it(vec.name + " should fail without Web Crypto", async function () {
                    withoutWebCrypto()
                    const d = new Decrypter()
                    d.addIdentity(vec.meta.identity)
                    await expect(async () => await d.decrypt(body())).rejects.toThrow()
                })
            }
        }
    }
})

function withoutWebCrypto() {
    forceWebCryptoOff(true)
    onTestFinished(() => { forceWebCryptoOff(false) })
}

function findSeparator(data: Uint8Array): number {
    for (let i = 0; i < data.length; i++) {
        if (data[i] === 0x0A && data[i + 1] === 0x0A) {
            return i
        }
    }
    throw Error("no separator found")
}
