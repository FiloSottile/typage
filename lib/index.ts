import sodium from "libsodium-wrappers-sumo"
import { decode as decodeBech32, encode as encodeBech32 } from "bech32-buffer"
import { scryptUnwrap, scryptWrap, x25519Identity, x25519Unwrap, x25519Wrap } from "./recipients.js"
import { encodeHeader, encodeHeaderNoMAC, parseHeader, Stanza } from "./format.js"
import { decryptSTREAM, encryptSTREAM } from "./stream.js"
import { HKDF } from "./hkdf.js"

interface age {
  Encrypter: new () => Encrypter;
  Decrypter: new () => Decrypter;
  generateIdentity: () => string;
  identityToRecipient: (identity: string) => string;
}

let initDone = false

export default async function init(): Promise<age> {
  if (!initDone) {
    await sodium.ready
    initDone = true
  }
  return {
    Encrypter: Encrypter,
    Decrypter: Decrypter,
    generateIdentity: generateIdentity,
    identityToRecipient: identityToRecipient,
  }
}

function generateIdentity(): string {
  const scalar = sodium.randombytes_buf(sodium.crypto_scalarmult_curve25519_SCALARBYTES)
  return encodeBech32("AGE-SECRET-KEY-", scalar)
}

function identityToRecipient(identity: string): string {
  const res = decodeBech32(identity)
  if (!identity.startsWith("AGE-SECRET-KEY-1") ||
    res.prefix.toUpperCase() !== "AGE-SECRET-KEY-" || res.encoding !== "bech32" ||
    res.data.length !== sodium.crypto_scalarmult_curve25519_SCALARBYTES)
    throw Error("invalid identity")

  const recipient = sodium.crypto_scalarmult_base(res.data)
  return encodeBech32("age", recipient)
}

class Encrypter {
  private passphrase: string | null = null
  private scryptWorkFactor = 18
  private recipients: Uint8Array[] = []

  setPassphrase(s: string): void {
    if (this.passphrase !== null)
      throw new Error("can encrypt to at most one passphrase")
    if (this.recipients.length !== 0)
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
      res.prefix.toLowerCase() !== "age" || res.encoding !== "bech32" ||
      res.data.length !== sodium.crypto_scalarmult_curve25519_BYTES)
      throw Error("invalid recipient")
    this.recipients.push(res.data)
  }

  encrypt(file: Uint8Array | string): Uint8Array {
    if (typeof file === "string") {
      file = sodium.from_string(file)
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

class Decrypter {
  private passphrases: string[] = []
  private identities: x25519Identity[] = []

  addPassphrase(s: string): void {
    this.passphrases.push(s)
  }

  addIdentity(s: string): void {
    const res = decodeBech32(s)
    if (!s.startsWith("AGE-SECRET-KEY-1") ||
      res.prefix.toUpperCase() !== "AGE-SECRET-KEY-" || res.encoding !== "bech32" ||
      res.data.length !== sodium.crypto_scalarmult_curve25519_SCALARBYTES)
      throw Error("invalid identity")
    this.identities.push({
      identity: res.data,
      recipient: sodium.crypto_scalarmult_base(res.data),
    })
  }

  decrypt(file: Uint8Array, outputFormat?: "uint8array"): Uint8Array
  decrypt(file: Uint8Array, outputFormat: "text"): string
  decrypt(file: Uint8Array, outputFormat?: "text" | "uint8array"): Uint8Array | string {
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
    if (outputFormat === "text") return sodium.to_string(out)
    return out
  }

  private unwrapFileKey(recipients: Stanza[]): Uint8Array | null {
    for (const s of recipients) {
      // Ideally this should be implemented by passing all stanzas to the scrypt
      // identity implementation, and letting it throw the error. In practice,
      // this is a very simple implementation with no public identity interface.
      if (s.args.length > 0 && s.args[0] === "scrypt" && recipients.length !== 1) {
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

export type { age, Encrypter, Decrypter }