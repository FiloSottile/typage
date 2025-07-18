import { describe } from "vitest"
import { test, fc } from "@fast-check/vitest"
import { Decrypter, Encrypter, generateIdentity, identityToRecipient } from "../lib/index.js"

fc.configureGlobal({
    // increasing this value will make fast-check do more random test runs,
    // which might be good for intensive testing, but also makes them slower.
    numRuns: typeof process !== "undefined" && process.env.SLOW ? 100 : 10,
})

const isEqualUInt8Array = (a: Uint8Array, b: Uint8Array) => {
    if (a.byteLength !== b.byteLength) {
        return false
    }

    for (let i = 0; i < a.byteLength; i++) {
        if (a[i] !== b[i]) {
            return false
        }
    }

    return true
}

describe("Property Based Tests", () => {
    describe("Asymmetric Encryption and Decryption", () => {
        test.prop(
            {
                plaintext: fc.string()
            }
        )(
            "decryption should invert encryption with identity/recipient (string plaintext)",
            async ({ plaintext }) => {
                const identity = await generateIdentity()
                const recipient = await identityToRecipient(identity)

                const enc = new Encrypter()
                const dec = new Decrypter()

                enc.addRecipient(recipient)
                dec.addIdentity(identity)

                return await dec.decrypt(await enc.encrypt(plaintext), "text") === plaintext
            }
        )

        test.prop(
            {
                plaintext: fc.uint8Array()
            }
        )(
            "decryption should invert encryption with identity/recipient (uint8array plaintext)",
            async ({ plaintext }) => {
                const identity = await generateIdentity()
                const recipient = await identityToRecipient(identity)

                const enc = new Encrypter()
                const dec = new Decrypter()

                enc.addRecipient(recipient)
                dec.addIdentity(identity)

                return isEqualUInt8Array(await dec.decrypt(await enc.encrypt(plaintext)), plaintext)
            }
        )
    })


    describe("Symmetric Encryption and Decryption", () => {
        test.prop(
            {
                plaintext: fc.string(),
                passphrase: fc.string(),
                scryptWorkFactor: fc.integer({ min: 1, max: 4 })
            }
        )(
            "decryption should invert encryption with passphrase (string plaintext)",
            async ({ plaintext, passphrase, scryptWorkFactor }) => {
                const enc = new Encrypter()
                const dec = new Decrypter()

                enc.setScryptWorkFactor(scryptWorkFactor)
                enc.setPassphrase(passphrase)
                dec.addPassphrase(passphrase)

                return await dec.decrypt(await enc.encrypt(plaintext), "text") === plaintext
            }
        )

        test.prop(
            {
                plaintext: fc.uint8Array(),
                passphrase: fc.string(),
                scryptWorkFactor: fc.integer({ min: 1, max: 4 })
            }
        )(
            "decryption should invert encryption with passphrase (UInt8Array plaintext)",
            async ({ plaintext, passphrase, scryptWorkFactor }) => {
                const enc = new Encrypter()
                const dec = new Decrypter()

                enc.setScryptWorkFactor(scryptWorkFactor)
                enc.setPassphrase(passphrase)
                dec.addPassphrase(passphrase)

                return isEqualUInt8Array(await dec.decrypt(await enc.encrypt(plaintext)), plaintext)
            }
        )
    })
})
