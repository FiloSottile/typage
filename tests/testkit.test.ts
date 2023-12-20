import { describe, it, assert } from "vitest"
import { readFileSync, readdirSync } from "fs"
import { encodeHeader, encodeHeaderNoMAC, parseHeader } from "../lib/format.js"
import { decryptSTREAM, encryptSTREAM } from "../lib/stream.js"
import { hkdf } from "@noble/hashes/hkdf"
import { sha256 } from "@noble/hashes/sha256"
import { hex } from "@scure/base"
import { Decrypter } from "../lib/index.js"

describe("CCTV testkit", function () {
    interface Vector {
        name: string,
        meta: Record<string, string>,
        body: Uint8Array,
    }
    const vectors: Vector[] = []
    for (const name of readdirSync("./tests/testkit")) {
        const contents = readFileSync("./tests/testkit/" + name)
        const sepIdx = contents.indexOf("\n\n")
        const header = contents.subarray(0, sepIdx).toString()
        const body = contents.subarray(sepIdx + 2)
        const vector: Vector = { name: name, meta: {}, body: body }
        for (const line of header.split("\n")) {
            const parts = line.split(": ", 2)
            vector.meta[parts[0]] = parts[1]
        }
        vectors.push(vector)
    }

    for (const vec of vectors) {
        if (vec.meta.armored) continue
        if (vec.meta.expect === "success") {
            it(vec.name + " should succeed", function () {
                const d = new Decrypter()
                if (vec.meta.passphrase)
                    d.addPassphrase(vec.meta.passphrase)
                if (vec.meta.identity)
                    d.addIdentity(vec.meta.identity)
                const plaintext = d.decrypt(vec.body)
                assert.equal(hex.encode(sha256(plaintext)), vec.meta.payload)
            })
            it(vec.name + " should round-trip header encoding", function () {
                const h = parseHeader(vec.body)
                assert.deepEqual(encodeHeaderNoMAC(h.recipients), h.headerNoMAC)
                const hh = encodeHeader(h.recipients, h.MAC)
                const got = new Uint8Array(hh.length + h.rest.length)
                got.set(hh)
                got.set(h.rest, hh.length)
                assert.deepEqual(got, vec.body)
            })
            it(vec.name + " should round-trip STREAM encryption", function () {
                const h = parseHeader(vec.body)
                const nonce = h.rest.subarray(0, 16)
                const streamKey = hkdf(sha256, hex.decode(vec.meta["file key"]), nonce, "payload", 32)
                const payload = h.rest.subarray(16)
                const plaintext = decryptSTREAM(streamKey, payload)
                assert.deepEqual(encryptSTREAM(streamKey, plaintext), payload)
            })
        } else {
            it(vec.name + " should fail", function () {
                const d = new Decrypter()
                if (vec.meta.passphrase)
                    d.addPassphrase(vec.meta.passphrase)
                if (vec.meta.identity)
                    d.addIdentity(vec.meta.identity)
                assert.throws(() => { d.decrypt(vec.body) })
            })
        }
    }
})
