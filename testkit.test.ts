import { strict as assert } from 'assert'
import { AgeDecrypter } from '.'
import { readFileSync, readdirSync } from 'fs'
import { crypto_hash_sha256, to_hex } from 'libsodium-wrappers-sumo';

describe('AgeDecrypter', function () {
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

    describe('decrypts the testkit files as expected', function () {
        for (const vec of vectors) {
            if (vec.meta.armored) continue
            if (vec.meta.expect == "success") {
                it(vec.name + " should succeed", async function () {
                    const d = new AgeDecrypter()
                    if (vec.meta.passphrase)
                        d.addPassphrase(vec.meta.passphrase)
                    if (vec.meta.identity)
                        d.addIdentity(vec.meta.identity)
                    const plaintext = await d.decrypt(vec.body)
                    assert.equal(to_hex(crypto_hash_sha256(plaintext)), vec.meta.payload)
                })
            } else {
                it(vec.name + " should fail", async function () {
                    const d = new AgeDecrypter()
                    if (vec.meta.passphrase)
                        d.addPassphrase(vec.meta.passphrase)
                    if (vec.meta.identity)
                        d.addIdentity(vec.meta.identity)
                    await assert.rejects(d.decrypt(vec.body))
                })
            }
        }
    })
});
