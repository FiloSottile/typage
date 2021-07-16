import { from_string } from "libsodium-wrappers-sumo"
import { HKDF as stableHKDF } from "@stablelib/hkdf"
import { SHA256 } from "@stablelib/sha256"

export function HKDF(salt: Uint8Array | null, label: string, secret: Uint8Array): Uint8Array {
    if (salt === null) { salt = new Uint8Array(32) }

    // const prk = sodium.crypto_auth_hmacsha256(secret, salt)
    // const infoAndCounter = new Uint8Array(label.length + 1)
    // infoAndCounter.set(from_string(label))
    // infoAndCounter[label.length] = 1
    // return sodium.crypto_auth_hmacsha256(infoAndCounter, prk)

    const h = new stableHKDF(SHA256, secret, salt, from_string(label))
    return h.expand(32)
}
