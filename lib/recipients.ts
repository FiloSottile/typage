import * as sodium from "libsodium-wrappers-sumo"
import { decodeBase64, encodeBase64, Stanza } from "./format.js"
import { HKDF } from "./hkdf.js"

export interface x25519Identity {
    identity: Uint8Array, recipient: Uint8Array,
}

export function x25519Wrap(fileKey: Uint8Array, recipient: Uint8Array): Stanza {
    const ephemeral = sodium.randombytes_buf(sodium.crypto_scalarmult_curve25519_SCALARBYTES)
    const share = sodium.crypto_scalarmult_base(ephemeral)
    const secret = sodium.crypto_scalarmult(ephemeral, recipient)

    const salt = new Uint8Array(share.length + recipient.length)
    salt.set(share)
    salt.set(recipient, share.length)

    const key = HKDF(secret, salt, "age-encryption.org/v1/X25519")
    return new Stanza(["X25519", encodeBase64(share)], encryptFileKey(fileKey, key))
}

export function x25519Unwrap(s: Stanza, i: x25519Identity): Uint8Array | null {
    if (s.args.length < 1 || s.args[0] != "X25519") {
        return null
    }
    if (s.args.length != 2) {
        throw Error("invalid X25519 stanza")
    }
    const share = decodeBase64(s.args[1])
    if (share.length !== sodium.crypto_scalarmult_curve25519_BYTES) {
        throw Error("invalid X25519 stanza")
    }

    const secret = sodium.crypto_scalarmult(i.identity, share)

    const salt = new Uint8Array(share.length + i.recipient.length)
    salt.set(share)
    salt.set(i.recipient, share.length)

    const key = HKDF(secret, salt, "age-encryption.org/v1/X25519")
    return decryptFileKey(s.body, key)
}

export function scryptWrap(fileKey: Uint8Array, passphrase: string, logN: number): Stanza {
    const salt = sodium.randombytes_buf(16)
    const label = "age-encryption.org/v1/scrypt"
    const labelAndSalt = new Uint8Array(label.length + 16)
    labelAndSalt.set(sodium.from_string(label))
    labelAndSalt.set(salt, label.length)

    const key = sodium.crypto_pwhash_scryptsalsa208sha256_ll(passphrase, labelAndSalt, 2 ** logN, 8, 1, 32)
    return new Stanza(["scrypt", encodeBase64(salt), logN.toString()], encryptFileKey(fileKey, key))
}

export function scryptUnwrap(s: Stanza, passphrase: string): Uint8Array | null {
    if (s.args.length < 1 || s.args[0] != "scrypt") {
        return null
    }
    if (s.args.length != 3) {
        throw Error("invalid scrypt stanza")
    }
    if (!/^[1-9][0-9]*$/.test(s.args[2])) {
        throw Error("invalid scrypt stanza")
    }
    const salt = decodeBase64(s.args[1])
    if (salt.length !== 16) {
        throw Error("invalid scrypt stanza")
    }

    const logN = Number(s.args[2])
    if (logN > 20) {
        throw Error("scrypt work factor is too high")
    }

    const label = "age-encryption.org/v1/scrypt"
    const labelAndSalt = new Uint8Array(label.length + 16)
    labelAndSalt.set(sodium.from_string(label))
    labelAndSalt.set(salt, label.length)

    const key = sodium.crypto_pwhash_scryptsalsa208sha256_ll(passphrase, labelAndSalt, 2 ** logN, 8, 1, 32)
    return decryptFileKey(s.body, key)
}

function encryptFileKey(fileKey: Uint8Array, key: Uint8Array): Uint8Array {
    const nonce = new Uint8Array(sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES)
    return sodium.crypto_aead_chacha20poly1305_ietf_encrypt(fileKey, null, null, nonce, key)
}

function decryptFileKey(body: Uint8Array, key: Uint8Array): Uint8Array | null {
    if (body.length !== 32) {
        throw Error("invalid stanza")
    }
    const nonce = new Uint8Array(sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES)
    try {
        return sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, body, null, nonce, key)
    } catch {
        return null
    }
}
