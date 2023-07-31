import * as sodium from "libsodium-wrappers-sumo"
import { from_string, to_string } from "libsodium-wrappers-sumo"
import { decode as decodeBech32, encode as encodeBech32 } from "bech32-buffer"
import { decodeBase64, encodeBase64, encodeHeader, encodeHeaderNoMAC, parseHeader, Stanza } from "./lib/format"
import { decryptSTREAM, encryptSTREAM } from "./lib/stream"
import { HKDF } from "./lib/hkdf"

export async function generateIdentity(): Promise<string> {
  await sodium.ready

  const scalar = sodium.randombytes_buf(sodium.crypto_scalarmult_curve25519_SCALARBYTES)
  return encodeBech32("AGE-SECRET-KEY-", scalar)
}

export async function identityToRecipient(identity: string): Promise<string> {
  await sodium.ready

  const res = decodeBech32(identity)
  if (!identity.startsWith("AGE-SECRET-KEY-1") ||
    res.prefix.toUpperCase() != "AGE-SECRET-KEY-" || res.encoding != "bech32" ||
    res.data.length != sodium.crypto_scalarmult_curve25519_SCALARBYTES)
    throw Error("invalid identity")

  const recipient = sodium.crypto_scalarmult_base(res.data)
  return encodeBech32("age", recipient)
}

export class Encrypter {
  private passphrase: string | null = null
  private scryptWorkFactor = 18
  private recipients: Uint8Array[] = []

  setPassphrase(s: string): void {
    if (this.passphrase !== null)
      throw new Error("can encrypt to at most one passphrase")
    if (this.recipients.length != 0)
      throw new Error("can't encrypt to both recipients and passphrases")
    this.passphrase = s
  }

  setScryptWorkFactor(logN: number): void {
    this.scryptWorkFactor = logN
  }

  addRecipient(s: string): void {
    if (this.passphrase !== null)
      throw new Error("can't encrypt to both recipients and passphrases")
    const res = decodeBech32(s)
    if (!s.startsWith("age1") ||
      res.prefix.toLowerCase() != "age" || res.encoding != "bech32" ||
      res.data.length != sodium.crypto_scalarmult_curve25519_BYTES)
      throw Error("invalid recipient")
    this.recipients.push(res.data)
  }

  async encrypt(file: Uint8Array | string): Promise<Uint8Array> {
    await sodium.ready

    if (typeof file === "string") {
      file = from_string(file)
    }

    const fileKey = sodium.randombytes_buf(16)
    const stanzas: Stanza[] = []

    for (const recipient of this.recipients) {
      stanzas.push(x25519Wrap(fileKey, recipient))
    }
    if (this.passphrase !== null) {
      stanzas.push(scryptWrap(fileKey, this.passphrase, this.scryptWorkFactor))
    }

    const hmacKey = HKDF(fileKey, null, "header")
    const mac = sodium.crypto_auth_hmacsha256(encodeHeaderNoMAC(stanzas), hmacKey)
    const header = encodeHeader(stanzas, mac)

    const nonce = sodium.randombytes_buf(16)
    const streamKey = HKDF(fileKey, nonce, "payload")
    const payload = encryptSTREAM(streamKey, file)

    const out = new Uint8Array(header.length + nonce.length + payload.length)
    out.set(header)
    out.set(nonce, header.length)
    out.set(payload, header.length + nonce.length)
    return out
  }
}

function x25519Wrap(fileKey: Uint8Array, recipient: Uint8Array): Stanza {
  const ephemeral = sodium.randombytes_buf(sodium.crypto_scalarmult_curve25519_SCALARBYTES)
  const share = sodium.crypto_scalarmult_base(ephemeral)
  const secret = sodium.crypto_scalarmult(ephemeral, recipient)

  const salt = new Uint8Array(share.length + recipient.length)
  salt.set(share)
  salt.set(recipient, share.length)

  const key = HKDF(secret, salt, "age-encryption.org/v1/X25519")
  return new Stanza(["X25519", encodeBase64(share)], encryptFileKey(fileKey, key))
}

function encryptFileKey(fileKey: Uint8Array, key: Uint8Array): Uint8Array {
  const nonce = new Uint8Array(sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES)
  return sodium.crypto_aead_chacha20poly1305_ietf_encrypt(fileKey, null, null, nonce, key)
}

function scryptWrap(fileKey: Uint8Array, passphrase: string, logN: number): Stanza {
  const salt = sodium.randombytes_buf(16)
  const label = "age-encryption.org/v1/scrypt"
  const labelAndSalt = new Uint8Array(label.length + 16)
  labelAndSalt.set(from_string(label))
  labelAndSalt.set(salt, label.length)

  const key = sodium.crypto_pwhash_scryptsalsa208sha256_ll(passphrase, labelAndSalt, 2 ** logN, 8, 1, 32)
  return new Stanza(["scrypt", encodeBase64(salt), logN.toString()], encryptFileKey(fileKey, key))
}

export class Decrypter {
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

  async decrypt(file: Uint8Array, outputFormat?: "uint8array"): Promise<Uint8Array>
  async decrypt(file: Uint8Array, outputFormat: "text"): Promise<string>
  async decrypt(file: Uint8Array, outputFormat?: "text" | "uint8array"): Promise<Uint8Array | string> {
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

    const out = decryptSTREAM(streamKey, payload)
    if (outputFormat === "text") return to_string(out)
    return out
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
