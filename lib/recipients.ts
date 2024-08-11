import { hkdf } from "@noble/hashes/hkdf"
import { sha256 } from "@noble/hashes/sha256"
import { scrypt } from "@noble/hashes/scrypt"
import { chacha20poly1305 } from "@noble/ciphers/chacha"
import { randomBytes } from "@noble/hashes/utils"
import { base64nopad } from "@scure/base"
import * as x25519 from "./x25519.js"
import { Stanza } from "./format.js"

export interface x25519Identity {
    identity: Uint8Array | CryptoKey, recipient: Promise<Uint8Array>,
}

export async function x25519Wrap(fileKey: Uint8Array, recipient: Uint8Array): Promise<Stanza> {
    const ephemeral = randomBytes(32)
    const share = await x25519.scalarMultBase(ephemeral)
    const secret = await x25519.scalarMult(ephemeral, recipient)

    const salt = new Uint8Array(share.length + recipient.length)
    salt.set(share)
    salt.set(recipient, share.length)

    const key = hkdf(sha256, secret, salt, "age-encryption.org/v1/X25519", 32)
    return new Stanza(["X25519", base64nopad.encode(share)], encryptFileKey(fileKey, key))
}

export async function x25519Unwrap(s: Stanza, i: x25519Identity): Promise<Uint8Array | null> {
    if (s.args.length < 1 || s.args[0] !== "X25519") {
        return null
    }
    if (s.args.length !== 2) {
        throw Error("invalid X25519 stanza")
    }
    const share = base64nopad.decode(s.args[1])
    if (share.length !== 32) {
        throw Error("invalid X25519 stanza")
    }

    const secret = await x25519.scalarMult(i.identity, share)

    const recipient = await i.recipient
    const salt = new Uint8Array(share.length + recipient.length)
    salt.set(share)
    salt.set(recipient, share.length)

    const key = hkdf(sha256, secret, salt, "age-encryption.org/v1/X25519", 32)
    return decryptFileKey(s.body, key)
}

export function scryptWrap(fileKey: Uint8Array, passphrase: string, logN: number): Stanza {
    const salt = randomBytes(16)
    const label = "age-encryption.org/v1/scrypt"
    const labelAndSalt = new Uint8Array(label.length + 16)
    labelAndSalt.set(new TextEncoder().encode(label))
    labelAndSalt.set(salt, label.length)

    const key = scrypt(passphrase, labelAndSalt, { N: 2 ** logN, r: 8, p: 1, dkLen: 32 })
    return new Stanza(["scrypt", base64nopad.encode(salt), logN.toString()], encryptFileKey(fileKey, key))
}

export function scryptUnwrap(s: Stanza, passphrase: string): Uint8Array | null {
    if (s.args.length < 1 || s.args[0] !== "scrypt") {
        return null
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

    const key = scrypt(passphrase, labelAndSalt, { N: 2 ** logN, r: 8, p: 1, dkLen: 32 })
    return decryptFileKey(s.body, key)
}

function encryptFileKey(fileKey: Uint8Array, key: Uint8Array): Uint8Array {
    const nonce = new Uint8Array(12)
    return chacha20poly1305(key, nonce).encrypt(fileKey)
}

function decryptFileKey(body: Uint8Array, key: Uint8Array): Uint8Array | null {
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
