import { bench } from "vitest"
import * as x25519 from "../lib/x25519.js"

const withWebCryptoOff = (f: () => Promise<void>) => async () => {
    x25519.forceWebCryptoOff(true)
    await f()
    x25519.forceWebCryptoOff(false)
}

const scalar = new Uint8Array(32).fill(42)
const point = await x25519.scalarMultBase(scalar)

bench("scalarMult/noble", withWebCryptoOff(async () => {
    await x25519.scalarMult(scalar, point)
}))
bench("scalarMultBase/noble", withWebCryptoOff(async () => {
    await x25519.scalarMultBase(scalar)
}))

await x25519.webCryptoFallback(async () => {
    const cryptoKey = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])
    if (cryptoKey instanceof CryptoKey) throw new Error("expected a CryptoKeyPair")

    bench("scalarMult/webcrypto", async () => {
        await x25519.scalarMult(scalar, point)
    })
    bench("scalarMultBase/webcrypto", async () => {
        await x25519.scalarMultBase(scalar)
    })

    bench("scalarMult/cryptokey", async () => {
        await x25519.scalarMult(cryptoKey.privateKey, point)
    })
    bench("scalarMultBase/cryptokey", async () => {
        await x25519.scalarMultBase(cryptoKey.privateKey)
    })
}, () => { /* no fallback needed */ })
