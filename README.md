<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://github.com/FiloSottile/age/blob/main/logo/logo_white.svg">
        <source media="(prefers-color-scheme: light)" srcset="https://github.com/FiloSottile/age/blob/main/logo/logo.svg">
        <img alt="The age logo, a wireframe of St. Peters dome in Rome, with the text: age, file encryption" width="600" src="https://github.com/FiloSottile/age/blob/main/logo/logo.svg">
    </picture>
</p>

[`age-encryption`](https://www.npmjs.com/package/age-encryption) is a TypeScript
implementation of the [age](https://age-encryption.org) file encryption format.

It depends only on the [noble](https://paulmillr.com/noble/) cryptography
libraries, and uses the Web Crypto API when available.

It also provides support for symmetric encryption using passkeys and hardware
security keys in the browser via WebAuthn, and an interoperable CLI plugin and
Go library for FIDO2 tokens.

## Installation

```sh
npm install age-encryption
```

## Usage

`age-encryption` is a modern ES Module with built-in types.

It's compiled for ES2022, and compatible with Node.js 18+, Bun, Deno, and all recent browsers.

#### Encrypt and decrypt a file with a new recipient / identity pair

```ts
import * as age from "age-encryption"

const identity = await age.generateIdentity()
const recipient = await age.identityToRecipient(identity)
console.log(identity)
console.log(recipient)

const e = new age.Encrypter()
e.addRecipient(recipient)
const ciphertext = await e.encrypt("Hello, age!")

const d = new age.Decrypter()
d.addIdentity(identity)
const out = await d.decrypt(ciphertext, "text")
console.log(out)
```

#### ASCII armoring

age encrypted files (the inputs of `Decrypter.decrypt` and outputs of
`Encrypter.encrypt`) are binary files, of type `Uint8Array`. There is an official ASCII
"armor" format, based on PEM, which provides a way to encode an encrypted file as text.

```ts
import * as age from "age-encryption"

const identity = await age.generateIdentity()
const recipient = await age.identityToRecipient(identity)
console.log(identity)
console.log(recipient)

const e = new age.Encrypter()
e.addRecipient(recipient)
const ciphertext = await e.encrypt("Hello, age!")
const armored = age.armor.encode(ciphertext)

console.log(armored)
// -----BEGIN AGE ENCRYPTED FILE-----
// YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB0QXVkQmNwZ3ZzYnNRZDJP
// WlFId3hyeFNmRS9SdUVUTkFhY1FXSno5VUFBClNOSWhEbnhoK21TaEs3SWRGdklw
// OW9pdlBZbDg3SEVSQ1FZZHBvUS90YjgKLS0tIGRCVXNNWmdJS0ZkNlNZbStPZWh4
// N2FBNUJZdTFxMmYwVTEzUWwvTFVNeUkKrNZnrZjMlXvoCHz0FUS/bp9129XtSV1Q
// 2twDjjAOwgBtBYoji9gKWgOG4w==
// -----END AGE ENCRYPTED FILE-----

const d = new age.Decrypter()
d.addIdentity(identity)
const decoded = age.armor.decode(armored)
const out = await d.decrypt(decoded, "text")
console.log(out)
```

#### Encrypt and decrypt a file with a passphrase

```ts
import { Encrypter, Decrypter } from "age-encryption"

const e = new Encrypter()
e.setPassphrase("burst-swarm-slender-curve-ability-various-crystal-moon-affair-three")
const ciphertext = await e.encrypt("Hello, age!")

const d = new Decrypter()
d.addPassphrase("burst-swarm-slender-curve-ability-various-crystal-moon-affair-three")
const out = await d.decrypt(ciphertext, "text")
console.log(out)
```

#### Encrypt and decrypt using the Streams API

You can also encrypt and decrypt [ReadableStreams][]. This can be useful for
encrypting or decrypting large files, requests, or responses on the fly.

```ts
import { Encrypter, Decrypter } from "age-encryption"

const file = new File([new TextEncoder().encode("age")], "age.txt")

const e = new Encrypter()
e.setScryptWorkFactor(12)
e.setPassphrase("light-original-energy-average-wish-blind-vendor-pencil-illness-scorpion")
const encryptedStream = await e.encrypt(file.stream())

const d = new Decrypter()
d.addPassphrase("light-original-energy-average-wish-blind-vendor-pencil-illness-scorpion")
const decryptedStream = await d.decrypt(encryptedStream)

console.log(await new Response(decryptedStream).text())
```

### Browser usage

`age-encryption` is compatible with modern bundlers such as [esbuild](https://esbuild.github.io/).

To produce a classic library file that sets `age` as a global variable, you can run

```sh
cd "$(mktemp -d)" && npm init -y && npm install esbuild age-encryption
npx esbuild --target=es2022 --bundle --minify --outfile=age.js --global-name=age age-encryption
```

or download a pre-built one from the [Releases page](https://github.com/FiloSottile/typage/releases).

<!-- TODO: why doesn't

  npx --package esbuild --package age-encryption -- esbuild ...

work? It should run esbuild in an environment where age-encryption is available. -->

Then, you can use it like this

```html
<script src="age.js"></script>
<script>
(async () => {
    const identity = await age.generateIdentity()
    const recipient = await age.identityToRecipient(identity)
    console.log(identity)
    console.log(recipient)

    const e = new age.Encrypter()
    e.addRecipient(recipient)
    const ciphertext = await e.encrypt("Hello, age!")

    const d = new age.Decrypter()
    d.addIdentity(identity)
    const out = await d.decrypt(ciphertext, "text")
    console.log(out)
})()
</script>
```

#### Encrypt and decrypt a file with a passkey

In the browser, `age-encryption` supports *symmetric* encryption with passkeys,
discoverable credentials that can be stored and synced by platforms (e.g. iCloud
Keychain) or password managers (e.g. 1Password).

This functionality uses the WebAuthn PRF extension, which is supported by recent
browsers and authenticators. When encrypting or decrypting a file, the user will
be prompted to select a passkey associated with the replying party ID (usually
the website origin). Passkeys not generated by `createCredential` can be used if
they have the `prf` extension enabled. The identity string returned by
`createCredential` can be optionally provided at encryption/decryption time to
prevent the user from selecting other passkeys.

```ts
await age.webauthn.createCredential({ keyName: "age encryption key 🦈" })

const e = new age.Encrypter()
e.addRecipient(new age.webauthn.WebAuthnRecipient())
const ciphertext = await e.encrypt("Hello, age!")
const armored = age.armor.encode(ciphertext)
console.log(armored)

const d = new age.Decrypter()
d.addIdentity(new age.webauthn.WebAuthnIdentity())
const decoded = age.armor.decode(armored)
const out = await d.decrypt(decoded, "text")
console.log(out)
```

Each encryption and decryption operation requires the authenticator and user
confirmation, there is no extractable key, and encrypted files can't be linked
to an identity or to each other without the ability to decrypt them.

#### Encrypt and decrypt a file with a security key

`age-encryption` also supports non-discoverable FIDO2 credentials, usually
useful to encrypt files with hardware security keys (e.g. YubiKeys).

Encryption and decryption work the same as with passkeys, but the identity
string is mandatory, because these credentials are not discoverable.

```ts
const identity = await age.webauthn.createCredential({
    type: "security-key", keyName: "age encryption key" })
console.log(identity) // AGE-PLUGIN-FIDO2PRF-1...

const e = new age.Encrypter()
e.addRecipient(new age.webauthn.WebAuthnRecipient({ identity: identity }))
const ciphertext = await e.encrypt("Hello, age!")
const armored = age.armor.encode(ciphertext)
console.log(armored)

const d = new age.Decrypter()
d.addIdentity(new age.webauthn.WebAuthnIdentity({ identity: identity }))
const decoded = age.armor.decode(armored)
const out = await d.decrypt(decoded, "text")
console.log(out)
```

##### age-plugin-fido2prf

If a credential is associated with a USB FIDO2 security key (e.g. a YubiKey),
its identity string can be used outside the browser with the provided
`age-plugin-fido2prf` plugin.

Files encrypted in the browser will decrypt from the CLI, and vice-versa. Since
WebAuthn encryption is symmetric, there is no recipient encoding, only
identities. To encrypt to an identity, use `age -e -i`.

```sh
go install filippo.io/typage/fido2prf/cmd/age-plugin-fido2prf@latest

cat << EOF > identity.txt
AGE-PLUGIN-FIDO2PRF-1Q9VGPY2E7S5FJJS3N7P03TZMMEJ94S6HYLDJLU8WVX2HP8SXQUGJUZ68LN6GP705662VS06UEX5J42W80NZT8Y2DQ8GTDN50VGATCNYLJ4HY2W5J67KYCTM858UFDCNUUDZ6U28WEMUKGVG9RNELRJDH8NFEP999Z8XFSS8XLS448A3TSQKWG9DMPL8ZCRRA02KSUC2UXTYDFNVYAE5KCMMRV9KXSMMNWJQKXATNVGTXV35G
EOF

age -d -i identity.txt << EOF
-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IGFnZS1lbmNyeXB0aW9uLm9yZy9maWRv
MnByZiBJSFFHd0poUkNSYThuVnB6b1R1bjdBClJ3d3dRUUtiRjN4TkU0VWx1SUZU
WnJtTVBFUTZoR0d4eUx2WXFOSFBsQzQKLS0tIFNWVGRnNzV4L00wblRENUZyYlFh
WU5wQmVsdG5hL0lmcXhTVzZHTVRtdFkK2rYiueXr8dgM1GiLVrBMC/LQRzkDacMw
GEtVcMZyh7b90z6VR3KT92EIlA==
-----END AGE ENCRYPTED FILE-----
EOF
```

Credentials can be generated from the command line with `age-plugin-fido2prf
-generate RPID`. Note that they will be usable inside the browser only if the
relying party ID matches the website's origin.

All the features of the plugin are also available as a Go library at
[filippo.io/typage/fido2prf](https://pkg.go.dev/filippo.io/typage/fido2prf).

#### Web Crypto identities

You can use a CryptoKey as an identity. It must have an `algorithm` of `X25519`,
and support the `deriveBits` key usage. It doesn't need to be extractable.

```ts
const keyPair = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])
const identity = (keyPair as CryptoKeyPair).privateKey
const recipient = await age.identityToRecipient(identity)
console.log(recipient)

const e = new age.Encrypter()
e.addRecipient(recipient)
const file = await e.encrypt("age")

const d = new age.Decrypter()
d.addIdentity(identity)
const out = await d.decrypt(file, "text")
console.log(out)
```

### Custom recipients and identities

You can implement the `Recipient` and `Identity` interfaces to use custom types
as recipients and identities.

This lets you use use remote APIs and secrets managers to wrap files keys, and
interoperate with [age plugins](https://github.com/FiloSottile/awesome-age?tab=readme-ov-file#plugins).
