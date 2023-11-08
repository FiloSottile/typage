import sodium from "libsodium-wrappers-sumo"

// @types/libsodium-wrappers-sumo is missing these definitions.
declare module "libsodium-wrappers-sumo" {
    export function crypto_auth_hmacsha256_init(key: Uint8Array): sodium.StateAddress
    export function crypto_auth_hmacsha256_update(stateAddress: sodium.StateAddress, messageChunk: Uint8Array): void
    export function crypto_auth_hmacsha256_final(stateAddress: sodium.StateAddress): Uint8Array
}

// HKDF extracts 32 bytes from HKDF-SHA-256 with the specified input key material, salt, and info.
export function HKDF(ikm: Uint8Array, salt: Uint8Array | null, info: string): Uint8Array {
    if (salt === null) { salt = new Uint8Array(32) }

    const h = sodium.crypto_auth_hmacsha256_init(salt)
    sodium.crypto_auth_hmacsha256_update(h, ikm)
    const prk = sodium.crypto_auth_hmacsha256_final(h)

    const infoAndCounter = new Uint8Array(info.length + 1)
    infoAndCounter.set(sodium.from_string(info))
    infoAndCounter[info.length] = 1

    return sodium.crypto_auth_hmacsha256(infoAndCounter, prk)
}
