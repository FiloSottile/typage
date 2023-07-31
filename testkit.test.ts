import * as assert from 'assert'
import { Decrypter } from '.'
import { readFileSync, readdirSync } from 'fs'
import { crypto_hash_sha256, from_hex, to_hex } from 'libsodium-wrappers-sumo'
import { encodeHeader, encodeHeaderNoMAC, parseHeader } from './lib/format'
import { decryptSTREAM, encryptSTREAM } from './lib/stream'
import { HKDF } from './lib/hkdf'

describe('CCTV testkit', function () {
    interface Vector {
        name: string,
        meta: Record<string, string>,
        body: Uint8Array,
    }
    const vectors: Vector[] = []
    for (const name of readdirSync('testkit')) {
        const contents = readFileSync('testkit/' + name)
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
        if (vec.meta.expect == "success") {
            it(vec.name + " should succeed", async function () {
                const d = new Decrypter()
                if (vec.meta.passphrase)
                    d.addPassphrase(vec.meta.passphrase)
                if (vec.meta.identity)
                    d.addIdentity(vec.meta.identity)
                const plaintext = await d.decrypt(vec.body)
                assert.equal(to_hex(crypto_hash_sha256(plaintext)), vec.meta.payload)
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
                const streamKey = HKDF(from_hex(vec.meta["file key"]), nonce, "payload")
                const payload = h.rest.subarray(16)
                const plaintext = decryptSTREAM(streamKey, payload)
                assert.deepEqual(encryptSTREAM(streamKey, plaintext), payload)
            })
        } else {
            it(vec.name + " should fail", async function () {
                const d = new Decrypter()
                if (vec.meta.passphrase)
                    d.addPassphrase(vec.meta.passphrase)
                if (vec.meta.identity)
                    d.addIdentity(vec.meta.identity)
                await assert.rejects(d.decrypt(vec.body))
            })
        }
    }
})
