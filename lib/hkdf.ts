import * as sodium from "libsodium-wrappers-sumo"
import { from_string } from "libsodium-wrappers-sumo"

declare module "libsodium-wrappers-sumo" {
    export function crypto_auth_hmacsha256_init(key: Uint8Array): sodium.StateAddress;
    export function crypto_auth_hmacsha256_update(stateAddress: sodium.StateAddress, messageChunk: Uint8Array): void;
    export function crypto_auth_hmacsha256_final(stateAddress: sodium.StateAddress): Uint8Array;
}

export function HKDF(salt: Uint8Array | null, label: string, secret: Uint8Array): Uint8Array {
    if (salt === null) { salt = new Uint8Array(32) }

    const h = sodium.crypto_auth_hmacsha256_init(salt)
    sodium.crypto_auth_hmacsha256_update(h, secret)
    const prk = sodium.crypto_auth_hmacsha256_final(h)

    const infoAndCounter = new Uint8Array(label.length + 1)
    infoAndCounter.set(from_string(label))
    infoAndCounter[label.length] = 1

    return sodium.crypto_auth_hmacsha256(infoAndCounter, prk)
}
