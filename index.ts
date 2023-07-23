import * as sodium from "libsodium-wrappers-sumo"
import { from_string } from "libsodium-wrappers-sumo"
import { decode as decodeBech32 } from "bech32-buffer"
import { decodeBase64, parseHeader, Stanza } from "./lib/format"
import { decryptSTREAM } from "./lib/stream"
import { HKDF } from "./lib/hkdf"

export class AgeDecrypter {
  private passphrases: string[] = []
  private identities: x25519Identity[] = []

  addPassphrase(s: string): void {
    this.passphrases.push(s)
  }

  addIdentity(s: string): void {
    const res = decodeBech32(s)
    if (!s.startsWith("AGE-SECRET-KEY-1") ||
      res.prefix.toUpperCase() != "AGE-SECRET-KEY-" || res.encoding != "bech32" ||
      res.data.length != sodium.crypto_scalarmult_curve25519_SCALARBYTES)
      throw Error("invalid identity")
    this.identities.push({
      identity: res.data,
      recipient: sodium.crypto_scalarmult_base(res.data),
    })
  }

  async decrypt(file: Uint8Array): Promise<Uint8Array> {
    await sodium.ready

    const h = parseHeader(file)
    const fileKey = this.unwrapFileKey(h.recipients)
    if (fileKey === null) {
      throw Error("no identity matched any of the file's recipients")
    }

    const hmacKey = HKDF(fileKey, null, "header")
    if (!sodium.crypto_auth_hmacsha256_verify(h.MAC, h.headerNoMAC, hmacKey)) {
      throw Error("invalid header HMAC")
    }

    const nonce = h.rest.subarray(0, 16)
    const streamKey = HKDF(fileKey, nonce, "payload")
    const payload = h.rest.subarray(16)

    return decryptSTREAM(streamKey, payload)
  }

  private unwrapFileKey(recipients: Stanza[]): Uint8Array | null {
    for (const s of recipients) {
      // Ideally this should be implemented by passing all stanzas to the scrypt
      // identity implementation, and letting it throw the error. In practice,
      // this is a very simple implementation with no public identity interface.
      if (s.args.length > 0 && s.args[0] == "scrypt" && recipients.length != 1) {
        throw Error("scrypt recipient is not the only one in the header")
      }

      for (const p of this.passphrases) {
        const k = scryptUnwrap(s, p)
        if (k !== null) { return k }
      }

      for (const i of this.identities) {
        const k = x25519Unwrap(s, i)
        if (k !== null) { return k }
      }
    }
    return null
  }
}

interface x25519Identity {
  identity: Uint8Array, recipient: Uint8Array,
}

function x25519Unwrap(s: Stanza, i: x25519Identity): Uint8Array | null {
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

function scryptUnwrap(s: Stanza, passphrase: string): Uint8Array | null {
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
  labelAndSalt.set(from_string(label))
  labelAndSalt.set(salt, label.length)

  const key = sodium.crypto_pwhash_scryptsalsa208sha256_ll(passphrase, labelAndSalt, 2 ** logN, 8, 1, 32)
  return decryptFileKey(s.body, key)
}
