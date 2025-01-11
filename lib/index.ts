import { hmac } from "@noble/hashes/hmac"
import { hkdf } from "@noble/hashes/hkdf"
import { sha256 } from "@noble/hashes/sha256"
import { randomBytes } from "@noble/hashes/utils"
import { ScryptIdentity, ScryptRecipient, X25519Identity, X25519Recipient } from "./recipients.js"
import { encodeHeader, encodeHeaderNoMAC, parseHeader, Stanza } from "./format.js"
import { decryptSTREAM, encryptSTREAM } from "./stream.js"

export * as armor from "./armor.js"

export * as webauthn from "./webauthn.js"

export { Stanza }

/**
 * An identity that can be used to decrypt a file key.
 *
 * This is a low-level interface that can be used to implement custom identity
 * types, such as plugins or remote APIs and secrets managers. Most users won't
 * need to interact with this directly, and should instead pass a string encoding
 * of a standard identity (`AGE-SECRET-KEY-1...`) to {@link Decrypter.addIdentity}.
 */
export interface Identity {
    /**
     * Decrypt a file key, if possible, using this identity. This function is
     * called during {@link Decrypter.decrypt}, once for each file.
     *
     * @param stanzas - All stanzas from the encrypted file's header. It is the
     * identity's responsibility to identify the stanzas it's expecting, if any.
     *
     * @returns The random file key, if this identity can decrypt it, or `null`
     * if none of the stanzas matched this identity.
     *
     * @throws `unwrapFileKey` must throw only if it identifies a stanza that
     * matches this identity, but the stanza is malformed or invalid, or
     * decryption fails due to external factors (e.g. network errors). For
     * example, it must return `null`, not throw, if the file is encrypted with
     * a different e.g. key.
     */
    unwrapFileKey(stanzas: Stanza[]): Uint8Array | null | Promise<Uint8Array | null>;
}

/**
 * A recipient that can be used to encrypt a file key.
 *
 * This is a low-level interface that can be used to implement custom recipient
 * types. Most users won't need to interact with this directly, and should
 * instead pass a string encoding of a standard recipient (`age1...`) to
 * {@link Encrypter.addRecipient}.
 */
export interface Recipient {
    /**
     * Encrypt a file key for this recipient. This function is called during
     * {@link Encrypter.encrypt}, once for each file.
     *
     * @param fileKey - The random file key to encrypt.
     *
     * @returns One or more stanzas that will be included (unencrypted) in the
     * encrypted file's header. The corresponding identity (which may be the
     * built-in X25519 or scrypt identity, or a custom {@link Identity}) must be
     * able to identify these stanzas, and use them to decrypt the file key.
     */
    wrapFileKey(fileKey: Uint8Array): Stanza[] | Promise<Stanza[]>;
}

export { generateIdentity, identityToRecipient } from "./recipients.js"

/**
 * Encrypts a file using the given passphrase or recipients.
 *
 * First, call {@link Encrypter.setPassphrase} to set a passphrase for symmetric
 * encryption, or {@link Encrypter.addRecipient} to specify one or more
 * recipients. Then, call {@link Encrypter.encrypt} one or more times to encrypt
 * files using the configured passphrase or recipients.
 */
export class Encrypter {
    private passphrase: string | null = null
    private scryptWorkFactor = 18
    private recipients: Recipient[] = []

    /**
     * Set the passphrase to encrypt the file(s) with. This method can only be
     * called once, and can't be called if {@link Encrypter.addRecipient} has
     * been called.
     *
     * The passphrase is passed through the scrypt key derivation function, but
     * it needs to have enough entropy to resist offline brute-force attacks.
     * You should use at least 8-10 random alphanumeric characters, or 4-5
     * random words from a list of at least 2000 words.
     *
     * @param s - The passphrase to encrypt the file with.
     */
    setPassphrase(s: string): void {
        if (this.passphrase !== null) {
            throw new Error("can encrypt to at most one passphrase")
        }
        if (this.recipients.length !== 0) {
            throw new Error("can't encrypt to both recipients and passphrases")
        }
        this.passphrase = s
    }

    /**
     * Set the scrypt work factor to use when encrypting the file(s) with a
     * passphrase. The default is 18. Using a lower value will require stronger
     * passphrases to resist offline brute-force attacks.
     *
     * @param logN - The base-2 logarithm of the scrypt work factor.
     */
    setScryptWorkFactor(logN: number): void {
        this.scryptWorkFactor = logN
    }

    /**
     * Add a recipient to encrypt the file(s) for. This method can be called
     * multiple times to encrypt the file(s) for multiple recipients.
     *
     * @param s - The recipient to encrypt the file for. Either a string
     * beginning with `age1...` or an object implementing the {@link Recipient}
     * interface.
     */
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

    /**
     * Encrypt a file using the configured passphrase or recipients.
     *
     * @param file - The file to encrypt. If a string is passed, it will be
     * encoded as UTF-8.
     *
     * @returns A promise that resolves to the encrypted file as a Uint8Array.
     */
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

/**
 * Decrypts a file using the given identities.
 *
 * First, call {@link Decrypter.addPassphrase} to set a passphrase for symmetric
 * decryption, and/or {@link Decrypter.addIdentity} to specify one or more
 * identities. All passphrases and/or identities are tried in parallel for each
 * file. Then, call {@link Decrypter.decrypt} one or more times to decrypt files
 * using the configured passphrase and/or identities.
 */
export class Decrypter {
    private identities: Identity[] = []

    /**
     * Add a passphrase to decrypt password-encrypted file(s) with. This method
     * can be called multiple times to try multiple passphrases.
     *
     * @param s - The passphrase to decrypt the file with.
     */
    addPassphrase(s: string): void {
        this.identities.push(new ScryptIdentity(s))
    }

    /**
     * Add an identity to decrypt file(s) with. This method can be called
     * multiple times to try multiple identities.
     *
     * @param s - The identity to decrypt the file with. Either a string
     * beginning with `AGE-SECRET-KEY-1...`, an X25519 private
     * {@link https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey | CryptoKey}
     * object, or an object implementing the {@link Identity} interface.
     *
     * A CryptoKey object must have
     * {@link https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/type | type}
     * `private`,
     * {@link https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/algorithm | algorithm}
     * `{name: 'X25519'}`, and
     * {@link https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/usages | usages}
     * `["deriveBits"]`. For example:
     * ```js
     * const keyPair = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])
     * decrypter.addIdentity(key.privateKey)
     * ```
     */
    addIdentity(s: string | CryptoKey | Identity): void {
        if (typeof s === "string" || isCryptoKey(s)) {
            this.identities.push(new X25519Identity(s))
        } else {
            this.identities.push(s)
        }
    }

    /**
     * Decrypt a file using the configured passphrases and/or identities.
     *
     * @param file - The file to decrypt.
     * @param outputFormat - The format to return the decrypted file in. If
     * `"text"` is passed, the file's plaintext will be decoded as UTF-8 and
     * returned as a string. Optional. It defaults to `"uint8array"`.
     *
     * @returns A promise that resolves to the decrypted file.
     */
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
