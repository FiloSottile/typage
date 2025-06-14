import { describe, it, assert, onTestFinished, expect } from "vitest"
import { Decrypter, Encrypter, generateIdentity, identityToRecipient } from "../lib/index.js"
import { forceWebCryptoOff, webCryptoFallback } from "../lib/x25519.js"
import { base64nopad } from "@scure/base"

describe("AgeDecrypter", function () {
    it("should decrypt a file with the right passphrase", async function () {
        const d = new Decrypter()
        d.addPassphrase("light-original-energy-average-wish-blind-vendor-pencil-illness-scorpion")
        const file = base64nopad.decode("YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4Y2lkcXJQdmwwZzRROEZ5eXU4dHNnIDgKNnM2Ylp2Vlg2b0NBSVp2QkxCZEhJbEJrYUcreWRIZHVHWVpBaUJkUy9ZMAotLS0gZ280TkNGT05VTDEwZW5WRjVPMnkxem05eWQwdkM0S09hSU1nV05aYW5QSQom4WH7RYXsjlDm3HNKCe9gY2IfCjTY/2t6PF4bzUkeWZWkE7kd")
        assert.equal(await d.decrypt(file, "text"), "test\n")
    })
    it("should decrypt a file with the right identity", async function () {
        const d = new Decrypter()
        d.addIdentity("AGE-SECRET-KEY-1L27NYJDYRNDSCCELNZE8C6JTSH22TLQJVPGD7289KDLMZA5HWN6SZPEHGF")
        const file = base64nopad.decode("YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBOb280UHUyVWZwTllzY3Z5OU1tTjlscHV1Smt4Nng0MEZkdGZoQzd1dVFZCmk0VUNvVmoxbEhHalV0bVR2MHFyRGl0YzNtMXdoY1oyVUtvWDU3MUQwR1EKLS0tIGJ1RTZSYmR6ZlNHSk5tSGl3U2hqR1FFUDF4eEdjSGZtbXlYQUN4SnM4RDAKyqdZXpg65sTtmakjxLONtEgaSwXeS8t+7jAWvlleVEFO4/9QIQ")
        assert.equal(await d.decrypt(file, "text"), "test\n")
    })
})

describe("key generation", function () {
    it("should encrypt and decrypt a file", async function () {
        const identity = await generateIdentity()
        const recipient = await identityToRecipient(identity)

        const e = new Encrypter()
        e.addRecipient(recipient)
        const file = await e.encrypt("age")

        const d = new Decrypter()
        d.addIdentity(identity)
        const out = await d.decrypt(file, "text")

        assert.equal(out, "age")
    })
})

describe("AgeEncrypter", function () {
    it("should encrypt (and decrypt) a file with a passphrase", async function () {
        const e = new Encrypter()
        e.setScryptWorkFactor(12)
        e.setPassphrase("light-original-energy-average-wish-blind-vendor-pencil-illness-scorpion")
        const file = await e.encrypt("age")

        const d = new Decrypter()
        d.addPassphrase("light-original-energy-average-wish-blind-vendor-pencil-illness-scorpion")
        const out = await d.decrypt(file, "text")

        assert.deepEqual(out, "age")
    })
    it("should encrypt (and decrypt) a file with a recipient", async function () {
        const e = new Encrypter()
        e.addRecipient("age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6")
        const file = await e.encrypt("age")

        const d = new Decrypter()
        d.addIdentity("AGE-SECRET-KEY-1RKH0DGHQ0FU6VLXX2VW6Y3W2TKK7KR4J36N9SNDXK75JHCJ3N6JQNZJF5J")
        const out = await d.decrypt(file, "text")

        assert.deepEqual(out, "age")
    })
    it("should encrypt (and decrypt) a file with multiple recipients", async function () {
        const e = new Encrypter()
        e.addRecipient("age12wv74vxhhp9kg29j2wzm50c9p4urn7py0t4tzdgz6m0pcqjzmu9qqpzjqn")
        e.addRecipient("age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6")
        const file = await e.encrypt("age")

        const d = new Decrypter()
        d.addIdentity("AGE-SECRET-KEY-1RKH0DGHQ0FU6VLXX2VW6Y3W2TKK7KR4J36N9SNDXK75JHCJ3N6JQNZJF5J")
        const out = await d.decrypt(file, "text")

        assert.deepEqual(out, "age")
    })
    it("should encrypt (and decrypt) a file with a CryptoKey", async function (context) {
        const keyPair = await webCryptoFallback(async () => {
            return await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])
        }, () => { return null })
        if (keyPair === null) {
            context.skip()
            return
        }
        if (keyPair instanceof CryptoKey) throw new Error("expected a CryptoKeyPair")
        const identity = keyPair.privateKey
        const recipient = await identityToRecipient(identity)

        const e = new Encrypter()
        e.addRecipient(recipient)
        const file = await e.encrypt("age")

        const d = new Decrypter()
        d.addIdentity(identity)
        const out = await d.decrypt(file, "text")

        assert.deepEqual(out, "age")
    })
    it("should encrypt (and decrypt) a file without Web Crypto", async function () {
        forceWebCryptoOff(true)
        onTestFinished(() => { forceWebCryptoOff(false) })

        const e = new Encrypter()
        e.addRecipient("age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6")
        const file = await e.encrypt("age")

        const d = new Decrypter()
        d.addIdentity("AGE-SECRET-KEY-1RKH0DGHQ0FU6VLXX2VW6Y3W2TKK7KR4J36N9SNDXK75JHCJ3N6JQNZJF5J")
        const out = await d.decrypt(file, "text")

        assert.deepEqual(out, "age")
    })
    it("should throw when using multiple passphrases", function () {
        const e = new Encrypter()
        e.setPassphrase("1")
        assert.throws(function () {
            e.setPassphrase("2")
        })
    })
    it("should throw when using passphrases and recipients", function () {
        const e = new Encrypter()
        e.setPassphrase("1")
        assert.throws(() => {
            e.addRecipient("age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6")
        })
    })
    it("should throw when using recipients and passphrases", function () {
        const e = new Encrypter()
        e.addRecipient("age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6")
        assert.throws(function () {
            e.setPassphrase("2")
        })
    })
    it("should throw when using bad recipients", function () {
        const e = new Encrypter()
        assert.throws(() => {
            e.addRecipient("age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl")
        })
        assert.throws(() => {
            e.addRecipient("AGE1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6")
        })
        assert.throws(() => {
            e.addRecipient("ag1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6")
        })
        assert.throws(() => {
            e.addRecipient("age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl7")
        })
    })
})

describe.skipIf(expect.getState().environment !== "node")("esbuild", function () {
    it("should tree shake", async function () {
        const result = await (await import("esbuild")).build({
            stdin: {
                // Not using "age-encryption" to load the TS files directly.
                contents: `import * as age from "./lib/index.js"`,
                resolveDir: __dirname + "/..",
            },
            bundle: true,
            write: false,
        })
        assert.equal(result.outputFiles.length, 1)
        assert.equal(result.outputFiles[0].text, "(() => {\n})();\n")
    })
})
