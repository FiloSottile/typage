import { x25519 } from "@noble/curves/ed25519"

const exportable = false

let webCryptoOff = false

export function forceWebCryptoOff(off: boolean) {
    webCryptoOff = off
}

export async function webCryptoFallback<Return>(
    func: () => Return | Promise<Return>,
    fallback: () => Return | Promise<Return>,
): Promise<Return> {
    if (webCryptoOff) {
        return await fallback()
    }
    // We can't reliably detect X25519 support in WebCrypto in a performant way
    // because Bun implemented importKey, but not deriveBits.
    // https://github.com/oven-sh/bun/issues/20148
    try {
        return await func()
    } catch (error) {
        if (error instanceof ReferenceError ||
            error instanceof DOMException && error.name === "NotSupportedError") {
            return await fallback()
        } else {
            throw error
        }
    }
}

export async function scalarMult(scalar: Uint8Array | CryptoKey, u: Uint8Array): Promise<Uint8Array> {
    return await webCryptoFallback(async () => {
        const key = isCryptoKey(scalar) ? scalar : await importX25519Key(scalar)
        const peer = await crypto.subtle.importKey("raw", u, { name: "X25519" }, exportable, [])
        // 256 bits is the fixed size of a X25519 shared secret. It's kind of
        // worrying that the WebCrypto API encourages truncating it.
        return new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: peer }, key, 256))
    }, () => {
        if (isCryptoKey(scalar)) {
            throw new Error("CryptoKey provided but X25519 WebCrypto is not supported")
        }
        return x25519.scalarMult(scalar, u)
    })
}

export async function scalarMultBase(scalar: Uint8Array | CryptoKey): Promise<Uint8Array> {
    return await webCryptoFallback(async () => {
        // The WebCrypto API simply doesn't support deriving public keys from
        // private keys. importKey returns only a CryptoKey (unlike generateKey
        // which returns a CryptoKeyPair) despite deriving the public key internally
        // (judging from the banchmarks, at least on Node.js). Our options are
        // exporting as JWK, deleting jwk.d, and re-importing (which only works for
        // exportable keys), or (re-)doing a scalar multiplication by the basepoint
        // manually. Here we do the latter.
        return scalarMult(scalar, x25519.GuBytes)
    }, () => {
        if (isCryptoKey(scalar)) {
            throw new Error("CryptoKey provided but X25519 WebCrypto is not supported")
        }
        return x25519.scalarMultBase(scalar)
    })
}

const pkcs8Prefix = /* @__PURE__ */ new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20])

async function importX25519Key(key: Uint8Array): Promise<CryptoKey> {
    // For some reason, the WebCrypto API only supports importing X25519 private
    // keys as PKCS #8 or JWK (even if it supports importing public keys as raw).
    // Thankfully since they are always the same length, we can just prepend a
    // fixed ASN.1 prefix for PKCS #8.
    if (key.length !== 32) {
        throw new Error("X25519 private key must be 32 bytes")
    }
    const pkcs8 = new Uint8Array([...pkcs8Prefix, ...key])
    // Annoyingly, importKey (at least on Node.js) computes the public key, which
    // is a waste if we're only going to run deriveBits.
    return crypto.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, exportable, ["deriveBits"])
}

function isCryptoKey(key: unknown): key is CryptoKey {
    return typeof CryptoKey !== "undefined" && key instanceof CryptoKey
}
