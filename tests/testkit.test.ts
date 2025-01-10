import { describe, it, assert, expect, onTestFinished } from "vitest"
import { encodeHeader, encodeHeaderNoMAC, parseHeader } from "../lib/format.js"
import { decryptSTREAM, encryptSTREAM } from "../lib/stream.js"
import { forceWebCryptoOff } from "../lib/x25519.js"
import { hkdf } from "@noble/hashes/hkdf"
import { sha256 } from "@noble/hashes/sha256"
import { hex, base64 } from "@scure/base"
import { Decrypter } from "../lib/index.js"

declare module "@vitest/browser/context" {
    interface BrowserCommands {
        listTestkitFiles: () => Promise<string[]>
        readTestkitFile: (name: string) => Promise<string>
    }
}

let listTestkitFiles: () => Promise<string[]>
let readTestkitFile: (name: string) => Promise<Uint8Array>
if (expect.getState().environment === "node") {
    const { readdir, readFile } = await import("fs/promises")
    listTestkitFiles = () => readdir("./tests/testkit")
    readTestkitFile = (name) => readFile("./tests/testkit/" + name)
} else {
    const { commands } = await import("@vitest/browser/context")
    listTestkitFiles = commands.listTestkitFiles
    readTestkitFile = async (name) => base64.decode(await commands.readTestkitFile(name))
}

describe("CCTV testkit", async function () {
    interface Vector {
        name: string,
        meta: Record<string, string>,
        body: Uint8Array,
    }
    const vectors: Vector[] = []
    for (const name of await listTestkitFiles()) {
        const contents = await readTestkitFile(name)
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
        vectors.push(vector)
    }

    for (const vec of vectors) {
        if (vec.meta.armored) continue
        if (vec.meta.expect === "success") {
            it(vec.name + " should succeed", async function () {
                const d = new Decrypter()
                if (vec.meta.passphrase) d.addPassphrase(vec.meta.passphrase)
                if (vec.meta.identity) d.addIdentity(vec.meta.identity)
                const plaintext = await d.decrypt(vec.body)
                assert.equal(hex.encode(sha256(plaintext)), vec.meta.payload)
            })
            if (vec.meta.identity) {
                it(vec.name + " should succeed without Web Crypto", async function () {
                    withoutWebCrypto()
                    const d = new Decrypter()
                    d.addIdentity(vec.meta.identity)
                    const plaintext = await d.decrypt(vec.body)
                    assert.equal(hex.encode(sha256(plaintext)), vec.meta.payload)
                })
            }
            it(vec.name + " should round-trip header encoding", function () {
                const h = parseHeader(vec.body)
                assert.deepEqual(encodeHeaderNoMAC(h.stanzas), h.headerNoMAC)
                const hh = encodeHeader(h.stanzas, h.MAC)
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
            it(vec.name + " should fail", async function () {
                const d = new Decrypter()
                if (vec.meta.passphrase) d.addPassphrase(vec.meta.passphrase)
                if (vec.meta.identity) d.addIdentity(vec.meta.identity)
                await expect(d.decrypt(vec.body)).rejects.toThrow()
            })
            if (vec.meta.identity) {
                it(vec.name + " should fail without Web Crypto", async function () {
                    withoutWebCrypto()
                    const d = new Decrypter()
                    d.addIdentity(vec.meta.identity)
                    await expect(d.decrypt(vec.body)).rejects.toThrow()
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
    return -1
}
