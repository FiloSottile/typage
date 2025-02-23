import { bech32 } from "@scure/base"
import { hkdf } from "@noble/hashes/hkdf"
import { sha256 } from "@noble/hashes/sha256"
import { scrypt } from "@noble/hashes/scrypt"
import { chacha20poly1305 } from "@noble/ciphers/chacha"
import { randomBytes } from "@noble/hashes/utils"
import { base64nopad } from "@scure/base"
import * as x25519 from "./x25519.js"
import { Stanza } from "./format.js"
import { Identity, Recipient } from "./index.js"

/**
 * Generate a new native age identity.
 *
 * @returns A promise that resolves to the new identity, a string starting with
 * `AGE-SECRET-KEY-1...`. Use {@link identityToRecipient} to produce the
 * corresponding recipient.
 */
export function generateIdentity(): Promise<string> {
    const scalar = randomBytes(32)
    const identity = bech32.encodeFromBytes("AGE-SECRET-KEY-", scalar).toUpperCase()
    return Promise.resolve(identity)
}

/**
 * Convert an age identity to a recipient.
 *
 * @param identity - An age identity, a string starting with
 * `AGE-SECRET-KEY-1...` or an X25519 private
 * {@link https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey | CryptoKey}
 * object.
 *
 * @returns A promise that resolves to the corresponding recipient, a string
 * starting with `age1...`.
 *
 * @see {@link generateIdentity}
 * @see {@link Decrypter.addIdentity}
 */
export async function identityToRecipient(identity: string | CryptoKey): Promise<string> {
    let scalar: Uint8Array | CryptoKey
    if (isCryptoKey(identity)) {
        scalar = identity
    } else {
        const res = bech32.decodeToBytes(identity)
        if (!identity.startsWith("AGE-SECRET-KEY-1") ||
            res.prefix.toUpperCase() !== "AGE-SECRET-KEY-" ||
            res.bytes.length !== 32) { throw Error("invalid identity") }
        scalar = res.bytes
    }

    const recipient = await x25519.scalarMultBase(scalar)
    return bech32.encodeFromBytes("age", recipient)
}

export class X25519Recipient implements Recipient {
    private recipient: Uint8Array

    constructor(s: string) {
        const res = bech32.decodeToBytes(s)
        if (!s.startsWith("age1") ||
            res.prefix.toLowerCase() !== "age" ||
            res.bytes.length !== 32) { throw Error("invalid recipient") }
        this.recipient = res.bytes
    }

    async wrapFileKey(fileKey: Uint8Array): Promise<Stanza[]> {
        const ephemeral = randomBytes(32)
        const share = await x25519.scalarMultBase(ephemeral)
        const secret = await x25519.scalarMult(ephemeral, this.recipient)

        const salt = new Uint8Array(share.length + this.recipient.length)
        salt.set(share)
        salt.set(this.recipient, share.length)

        const key = hkdf(sha256, secret, salt, "age-encryption.org/v1/X25519", 32)
        return [new Stanza(["X25519", base64nopad.encode(share)], encryptFileKey(fileKey, key))]
    }
}

export class X25519Identity implements Identity {
    private identity: Uint8Array | CryptoKey
    private recipient: Promise<Uint8Array>

    constructor(s: string | CryptoKey) {
        if (isCryptoKey(s)) {
            this.identity = s
            this.recipient = x25519.scalarMultBase(s)
            return
        }
        const res = bech32.decodeToBytes(s)
        if (!s.startsWith("AGE-SECRET-KEY-1") ||
            res.prefix.toUpperCase() !== "AGE-SECRET-KEY-" ||
            res.bytes.length !== 32) { throw Error("invalid identity") }
        this.identity = res.bytes
        this.recipient = x25519.scalarMultBase(res.bytes)
    }

    async unwrapFileKey(stanzas: Stanza[]): Promise<Uint8Array | null> {
        for (const s of stanzas) {
            if (s.args.length < 1 || s.args[0] !== "X25519") {
                continue
            }
            if (s.args.length !== 2) {
                throw Error("invalid X25519 stanza")
            }
            const share = base64nopad.decode(s.args[1])
            if (share.length !== 32) {
                throw Error("invalid X25519 stanza")
            }

            const secret = await x25519.scalarMult(this.identity, share)

            const recipient = await this.recipient
            const salt = new Uint8Array(share.length + recipient.length)
            salt.set(share)
            salt.set(recipient, share.length)

            const key = hkdf(sha256, secret, salt, "age-encryption.org/v1/X25519", 32)
            const fileKey = decryptFileKey(s.body, key)
            if (fileKey !== null) return fileKey
        }
        return null
    }
}

export class ScryptRecipient implements Recipient {
    private passphrase: string
    private logN: number

    constructor(passphrase: string, logN: number) {
        this.passphrase = passphrase
        this.logN = logN
    }

    wrapFileKey(fileKey: Uint8Array): Stanza[] {
        const salt = randomBytes(16)
        const label = "age-encryption.org/v1/scrypt"
        const labelAndSalt = new Uint8Array(label.length + 16)
        labelAndSalt.set(new TextEncoder().encode(label))
        labelAndSalt.set(salt, label.length)

        const key = scrypt(this.passphrase, labelAndSalt, { N: 2 ** this.logN, r: 8, p: 1, dkLen: 32 })
        return [new Stanza(["scrypt", base64nopad.encode(salt), this.logN.toString()], encryptFileKey(fileKey, key))]
    }
}

export class ScryptIdentity implements Identity {
    private passphrase: string

    constructor(passphrase: string) {
        this.passphrase = passphrase
    }

    unwrapFileKey(stanzas: Stanza[]): Uint8Array | null {
        for (const s of stanzas) {
            if (s.args.length < 1 || s.args[0] !== "scrypt") {
                continue
            }
            if (stanzas.length !== 1) {
                throw Error("scrypt recipient is not the only one in the header")
            }
            if (s.args.length !== 3) {
                throw Error("invalid scrypt stanza")
            }
            if (!/^[1-9][0-9]*$/.test(s.args[2])) {
                throw Error("invalid scrypt stanza")
            }
            const salt = base64nopad.decode(s.args[1])
            if (salt.length !== 16) {
                throw Error("invalid scrypt stanza")
            }

            const logN = Number(s.args[2])
            if (logN > 20) {
                throw Error("scrypt work factor is too high")
            }

            const label = "age-encryption.org/v1/scrypt"
            const labelAndSalt = new Uint8Array(label.length + 16)
            labelAndSalt.set(new TextEncoder().encode(label))
            labelAndSalt.set(salt, label.length)

            const key = scrypt(this.passphrase, labelAndSalt, { N: 2 ** logN, r: 8, p: 1, dkLen: 32 })
            const fileKey = decryptFileKey(s.body, key)
            if (fileKey !== null) return fileKey
        }
        return null
    }
}

export function encryptFileKey(fileKey: Uint8Array, key: Uint8Array): Uint8Array {
    const nonce = new Uint8Array(12)
    return chacha20poly1305(key, nonce).encrypt(fileKey)
}

export function decryptFileKey(body: Uint8Array, key: Uint8Array): Uint8Array | null {
    if (body.length !== 32) {
        throw Error("invalid stanza")
    }
    const nonce = new Uint8Array(12)
    try {
        return chacha20poly1305(key, nonce).decrypt(body)
    } catch {
        return null
    }
}

function isCryptoKey(key: unknown): key is CryptoKey {
    return typeof CryptoKey !== "undefined" && key instanceof CryptoKey
}
