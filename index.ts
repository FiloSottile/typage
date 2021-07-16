import * as sodium from "libsodium-wrappers-sumo"
import { from_base64, base64_variants, from_string } from "libsodium-wrappers-sumo"
import { parseHeader, Stanza } from "./lib/format"
import { HKDF } from "./lib/hkdf"

export class AgeDecrypter {
  identities: string[] = []

  addPassphrase(s: string): void {
    this.identities.push(s)
  }

  async decrypt(file: Uint8Array): Promise<Uint8Array> {
    await sodium.ready

    let fileKey: Uint8Array | null = null
    const h = parseHeader(file)
    for (const s of h.recipients) {
      if (s.args[0] != "scrypt") {
        continue
      }
      for (const p of this.identities) {
        const k = scryptUnwrap(s, p)
        if (k !== null) { fileKey = k }
      }
    }
    if (fileKey === null) {
      throw Error("no identity matched any of the file's recipients")
    }

    const hmacKey = HKDF(null, "header", fileKey)
    if (!sodium.crypto_auth_hmacsha256_verify(h.MAC, h.headerNoMAC, hmacKey)) {
      throw Error("invalid header HMAC")
    }

    const nonce = h.rest.subarray(0, 16)
    const streamKey = HKDF(nonce, "payload", fileKey)
    const payload = h.rest.subarray(16)

    // TODO: actual STREAM implementation
    const streamNonce = new Uint8Array(12)
    streamNonce[11] = 1

    return sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, payload, null, streamNonce, streamKey)
  }
}

function scryptUnwrap(s: Stanza, passphrase: string): Uint8Array | null {
  if (s.args[0] != "scrypt") {
    throw Error("invalid scrypt stanza")
  }
  if (s.args.length != 3) {
    throw Error("invalid scrypt stanza")
  }
  if (!/^\d+$/.test(s.args[2])) {
    throw Error("invalid scrypt stanza")
  }
  const salt = from_base64(s.args[1], base64_variants.ORIGINAL_NO_PADDING)
  if (salt.length !== 16) {
    throw Error("invalid scrypt stanza")
  }

  const logN = Number(s.args[2])
  const label = "age-encryption.org/v1/scrypt"
  const labelAndSalt = new Uint8Array(label.length + 16)
  labelAndSalt.set(from_string(label))
  labelAndSalt.set(salt, label.length)

  const key = sodium.crypto_pwhash_scryptsalsa208sha256_ll(passphrase, labelAndSalt, 2 ** logN, 8, 1, 32)
  const nonce = new Uint8Array(sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES)
  try {
    return sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, s.body, null, nonce, key)
  } catch {
    return null
  }
}
