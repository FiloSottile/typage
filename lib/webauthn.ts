import { bech32, base64nopad } from "@scure/base"
import { randomBytes } from "@noble/hashes/utils.js"
import { extract } from "@noble/hashes/hkdf.js"
import { sha256 } from "@noble/hashes/sha2.js"
import { type Identity, type Recipient } from "./index.js"
import { Stanza } from "./format.js"
import { decryptFileKey, encryptFileKey } from "./recipients.js"
import * as cbor from "./cbor.js"

/**
 * Options for {@link createCredential}.
 */
export interface CreationOptions {
    /**
     * The name of the key. This will be shown in various platform UIs.
     *
     * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#name_2 | PublicKeyCredentialCreationOptions.user.name}
     */
    keyName: string;

    /**
     * The type of credential to create.
     *
     * If the default `passkey` is used, the credential will be required to be
     * discoverable. This means that the user will be able to select it from a
     * list of credentials even if {@link Options.identity} is not set.
     *
     * If `security-key` is used, the `security-key` hint and the `discouraged`
     * residentKey option will be passed to the authenticator. The returned
     * identity string MUST be passed with {@link Options.identity} to encrypt
     * and decrypt files, and CAN'T be regenerated if lost. The UI will prompt
     * the user to use a hardware token. The returned identity might also be
     * usable with age-plugin-fido2prf outside the browser.
     *
     * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#residentkey | PublicKeyCredentialCreationOptions.authenticatorSelection.residentKey}
     * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#hints | PublicKeyCredentialCreationOptions.hints}
     */
    type?: "passkey" | "security-key";

    /**
     * The relying party ID to use for the WebAuthn credential.
     *
     * This must be the origin's domain (e.g. `app.example.com`), or a parent
     * (e.g. `example.com`). Note that credentials are available to subdomains
     * of the RP ID, but not to parents, so it's important to choose the right
     * RP ID.
     *
     * @see {@link https://www.imperialviolet.org/tourofwebauthn/tourofwebauthn.html#relying-party-ids | A Tour of WebAuthn § Relying party IDs}
     * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#id_2 | PublicKeyCredentialCreationOptions.rp.id}
     */
    rpId?: string;
}

// We don't actually use the public key, so declare support for all default
// algorithms that might be supported by authenticators.
const defaultAlgorithms: PublicKeyCredentialParameters[] = [
    { type: "public-key", alg: -8 }, // Ed25519
    { type: "public-key", alg: -7 }, // ECDSA with P-256 and SHA-256
    { type: "public-key", alg: -257 }, // RSA PKCS#1 v1.5 with SHA-256
]

// The hints property is not yet in TypeScript's DOM types.
// https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#hints
type CredentialHints = ("security-key" | "client-device" | "hybrid")[]

/**
 * Creates a new WebAuthn credential which can be used for encryption and
 * decryption.
 *
 * @returns The identity string to use for encryption or decryption.
 *
 * This string begins with `AGE-PLUGIN-FIDO2PRF-1...` and encodes the credential ID,
 * the relying party ID, and the transport hint.
 *
 * If the credential was created with {@link CreationOptions."type"} set to the
 * default `passkey`, this string is mostly a hint to make selecting the
 * credential easier. If the credential was created with `security-key`, this
 * string is required to encrypt and decrypt files, and can't be regenerated if
 * lost.
 *
 * @see {@link Options.identity}
 * @experimental
 */
export async function createCredential(options: CreationOptions): Promise<string> {
    const cred = await navigator.credentials.create({
        publicKey: {
            rp: { name: "", id: options.rpId },
            user: {
                name: options.keyName,
                id: domBuffer(randomBytes(8)), // avoid overwriting existing keys
                displayName: "",
            },
            pubKeyCredParams: defaultAlgorithms,
            authenticatorSelection: {
                requireResidentKey: options.type !== "security-key",
                residentKey: options.type !== "security-key" ? "required" : "discouraged",
                userVerification: "required", // prf requires UV
            },
            hints: options.type === "security-key" ? ["security-key"] : [],
            extensions: { prf: {} },
            challenge: new Uint8Array([0]).buffer, // unused without attestation
        } as PublicKeyCredentialCreationOptions & { hints?: CredentialHints },
    }) as PublicKeyCredential
    if (!cred.getClientExtensionResults().prf?.enabled) {
        throw Error("PRF extension not available (need macOS 15+, Chrome 132+)")
    }
    // Annoyingly, it doesn't seem possible to get the RP ID from the
    // credential, so we have to hope we get the default right.
    const rpId = options.rpId ?? new URL(window.origin).hostname
    return encodeIdentity(cred, rpId)
}

const prefix = "AGE-PLUGIN-FIDO2PRF-"

function encodeIdentity(credential: PublicKeyCredential, rpId: string): string {
    const res = credential.response as AuthenticatorAttestationResponse
    const version = cbor.encodeUint(1)
    const credId = cbor.encodeByteString(new Uint8Array(credential.rawId))
    const rp = cbor.encodeTextString(rpId)
    const transports = cbor.encodeArray(res.getTransports())
    const identityData = new Uint8Array([...version, ...credId, ...rp, ...transports])
    return bech32.encode(prefix, bech32.toWords(identityData), false).toUpperCase()
}

function decodeIdentity(identity: string): [Uint8Array, string, string[]] {
    const res = bech32.decodeToBytes(identity)
    if (!identity.startsWith(prefix + "1")) {
        throw Error("invalid identity")
    }
    const [version, rest1] = cbor.readUint(res.bytes)
    if (version !== 1) {
        throw Error("unsupported identity version")
    }
    const [credId, rest2] = cbor.readByteString(rest1)
    const [rpId, rest3] = cbor.readTextString(rest2)
    const [transports,] = cbor.readArray(rest3)
    return [credId, rpId, transports]
}

/**
 * Options for {@link WebAuthnRecipient} and {@link WebAuthnIdentity}.
 */
export interface Options {
    /**
     * The identity string to use for encryption or decryption.
     *
     * If set, the file will be encrypted or decrypted with this specific
     * credential. Otherwise, the user will be prompted to select a discoverable
     * credential from those available for the RP (which might include login
     * credentials, which won't work).
     *
     * @see {@link createCredential}
     */
    identity?: string;

    /**
     * The relying party ID for discoverable credentials. Ignored if
     * {@link identity} is set, as the RP ID is parsed from the identity.
     *
     * @see {@link CreationOptions.rpId}
     * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions#rpid | PublicKeyCredentialRequestOptions.rpId}
     */
    rpId?: string;
}

const label = "age-encryption.org/fido2prf"

class WebAuthnInternal {
    private credId: Uint8Array | undefined
    private transports: string[] | undefined
    private rpId: string | undefined

    constructor(options?: Options) {
        if (options?.identity) {
            const [credId, rpId, transports] = decodeIdentity(options.identity)
            this.credId = credId
            this.transports = transports
            this.rpId = rpId
        } else {
            this.rpId = options?.rpId
        }
    }

    protected async getCredential(nonce: Uint8Array): Promise<AuthenticationExtensionsPRFValues> {
        const assertion = await navigator.credentials.get({
            publicKey: {
                allowCredentials: this.credId ? [{
                    id: domBuffer(this.credId),
                    transports: this.transports as AuthenticatorTransport[],
                    type: "public-key"
                }] : [],
                challenge: domBuffer(randomBytes(16)),
                extensions: { prf: { eval: prfInputs(nonce) } },
                userVerification: "required", // prf requires UV
                rpId: this.rpId,
            },
        }) as PublicKeyCredential
        const results = assertion.getClientExtensionResults().prf?.results
        if (results === undefined) {
            throw Error("PRF extension not available (need macOS 15+, Chrome 132+)")
        }
        return results
    }
}

// For the WebAuthnRecipient and WebAuthnIdentity TSDoc links.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import { type Encrypter, type Decrypter } from "./index.js"

/**
 * A {@link Recipient} that symmetrically encrypts file keys using a WebAuthn
 * credential, such as a passkey or a security key.
 *
 * The credential needs to already exist, and support the PRF extension.
 * Usually, it would have been created with {@link createCredential}.
 *
 * @see {@link Encrypter.addRecipient}
 * @experimental
 */
export class WebAuthnRecipient extends WebAuthnInternal implements Recipient {
    /**
     * Implements {@link Recipient.wrapFileKey}.
     */
    async wrapFileKey(fileKey: Uint8Array): Promise<Stanza[]> {
        const nonce = randomBytes(16)
        const results = await this.getCredential(nonce)
        const key = deriveKey(results)
        return [new Stanza([label, base64nopad.encode(nonce)], encryptFileKey(fileKey, key))]
    }
}

/**
 * An {@link Identity} that symmetrically decrypts file keys using a WebAuthn
 * credential, such as a passkey or a security key.
 *
 * The credential needs to already exist, and support the PRF extension.
 * Usually, it would have been created with {@link createCredential}.
 *
 * @see {@link Decrypter.addIdentity}
 * @experimental
 */
export class WebAuthnIdentity extends WebAuthnInternal implements Identity {
    /**
     * Implements {@link Identity.unwrapFileKey}.
     */
    async unwrapFileKey(stanzas: Stanza[]): Promise<Uint8Array | null> {
        for (const s of stanzas) {
            if (s.args.length < 1 || s.args[0] !== label) {
                continue
            }
            if (s.args.length !== 2) {
                throw Error("invalid prf stanza")
            }
            const nonce = base64nopad.decode(s.args[1])
            if (nonce.length !== 16) {
                throw Error("invalid prf stanza")
            }

            const results = await this.getCredential(nonce)
            const key = deriveKey(results)
            const fileKey = decryptFileKey(s.body, key)
            if (fileKey !== null) return fileKey
        }
        return null
    }
}

// We use both first and second to prevent an attacker from decrypting two files
// at once with a single user presence check.

function prfInputs(nonce: Uint8Array): AuthenticationExtensionsPRFValues {
    const prefix = new TextEncoder().encode(label)

    const first = new Uint8Array(prefix.length + nonce.length + 1)
    first.set(prefix, 0)
    first[prefix.length] = 0x01
    first.set(nonce, prefix.length + 1)

    const second = new Uint8Array(prefix.length + nonce.length + 1)
    second.set(prefix, 0)
    second[prefix.length] = 0x02
    second.set(nonce, prefix.length + 1)

    return { first, second }
}

function deriveKey(results: AuthenticationExtensionsPRFValues): Uint8Array {
    if (results.second === undefined) {
        throw Error("Missing second PRF result")
    }
    const prf = new Uint8Array(results.first.byteLength + results.second.byteLength)
    prf.set(new Uint8Array(results.first as ArrayBuffer), 0)
    prf.set(new Uint8Array(results.second as ArrayBuffer), results.first.byteLength)
    return extract(sha256, prf, new TextEncoder().encode(label))
}

// TypeScript 5.9+ made Uint8Array generic, defaulting to Uint8Array<ArrayBufferLike>.
// DOM APIs like WebAuthn require Uint8Array<ArrayBuffer> (no SharedArrayBuffer).
// This helper narrows the type while still catching non-Uint8Array arguments.
function domBuffer(arr: Uint8Array): Uint8Array<ArrayBuffer> {
    return arr as Uint8Array<ArrayBuffer>
}
