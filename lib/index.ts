import { hmac } from "@noble/hashes/hmac"
import { hkdf } from "@noble/hashes/hkdf"
import { sha256 } from "@noble/hashes/sha256"
import { randomBytes } from "@noble/hashes/utils"
import { ScryptIdentity, ScryptRecipient, X25519Identity, X25519Recipient } from "./recipients.js"
import { encodeHeader, encodeHeaderNoMAC, parseHeader, Stanza } from "./format.js"
import { decryptSTREAM, encryptSTREAM } from "./stream.js"

export { Stanza }

export interface Identity {
    unwrapFileKey(stanzas: Stanza[]): Uint8Array | null | Promise<Uint8Array | null>;
}

export interface Recipient {
    wrapFileKey(fileKey: Uint8Array): Stanza[] | Promise<Stanza[]>;
}

export { generateIdentity, identityToRecipient } from "./recipients.js"

export class Encrypter {
    private passphrase: string | null = null
    private scryptWorkFactor = 18
    private recipients: Recipient[] = []

    setPassphrase(s: string): void {
        if (this.passphrase !== null) {
            throw new Error("can encrypt to at most one passphrase")
        }
        if (this.recipients.length !== 0) {
            throw new Error("can't encrypt to both recipients and passphrases")
        }
        this.passphrase = s
    }

    setScryptWorkFactor(logN: number): void {
        this.scryptWorkFactor = logN
    }

    addRecipient(s: string | Recipient): void {
        if (this.passphrase !== null) {
            throw new Error("can't encrypt to both recipients and passphrases")
        }

        if (typeof s === "string") {
            this.recipients.push(new X25519Recipient(s))
        } else {
            this.recipients.push(s)
        }
    }

    async encrypt(file: Uint8Array | string): Promise<Uint8Array> {
        if (typeof file === "string") {
            file = new TextEncoder().encode(file)
        }

        const fileKey = randomBytes(16)
        const stanzas: Stanza[] = []

        let recipients = this.recipients
        if (this.passphrase !== null) {
            recipients = [new ScryptRecipient(this.passphrase, this.scryptWorkFactor)]
        }
        for (const recipient of recipients) {
            stanzas.push(...await recipient.wrapFileKey(fileKey))
        }

        const hmacKey = hkdf(sha256, fileKey, undefined, "header", 32)
        const mac = hmac(sha256, hmacKey, encodeHeaderNoMAC(stanzas))
        const header = encodeHeader(stanzas, mac)

        const nonce = randomBytes(16)
        const streamKey = hkdf(sha256, fileKey, nonce, "payload", 32)
        const payload = encryptSTREAM(streamKey, file)

        const out = new Uint8Array(header.length + nonce.length + payload.length)
        out.set(header)
        out.set(nonce, header.length)
        out.set(payload, header.length + nonce.length)
        return out
    }
}

export class Decrypter {
    private identities: Identity[] = []

    addPassphrase(s: string): void {
        this.identities.push(new ScryptIdentity(s))
    }

    addIdentity(s: string | CryptoKey | Identity): void {
        if (typeof s === "string" || isCryptoKey(s)) {
            this.identities.push(new X25519Identity(s))
        } else {
            this.identities.push(s)
        }
    }

    async decrypt(file: Uint8Array, outputFormat?: "uint8array"): Promise<Uint8Array>
    async decrypt(file: Uint8Array, outputFormat: "text"): Promise<string>
    async decrypt(file: Uint8Array, outputFormat?: "text" | "uint8array"): Promise<string | Uint8Array> {
        const h = parseHeader(file)
        const fileKey = await this.unwrapFileKey(h.stanzas)
        if (fileKey === null) {
            throw Error("no identity matched any of the file's recipients")
        }

        const hmacKey = hkdf(sha256, fileKey, undefined, "header", 32)
        const mac = hmac(sha256, hmacKey, h.headerNoMAC)
        if (!compareBytes(h.MAC, mac)) {
            throw Error("invalid header HMAC")
        }

        const nonce = h.rest.subarray(0, 16)
        const streamKey = hkdf(sha256, fileKey, nonce, "payload", 32)
        const payload = h.rest.subarray(16)

        const out = decryptSTREAM(streamKey, payload)
        if (outputFormat === "text") return new TextDecoder().decode(out)
        return out
    }

    private async unwrapFileKey(stanzas: Stanza[]): Promise<Uint8Array | null> {
        for (const identity of this.identities) {
            const fileKey = await identity.unwrapFileKey(stanzas)
            if (fileKey !== null) return fileKey
        }
        return null
    }
}

function compareBytes(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) { return false }
    let acc = 0
    for (let i = 0; i < a.length; i++) {
        acc |= a[i] ^ b[i]
    }
    return acc === 0
}

function isCryptoKey(key: unknown): key is CryptoKey {
    return typeof CryptoKey !== "undefined" && key instanceof CryptoKey
}
