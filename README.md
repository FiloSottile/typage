<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://github.com/FiloSottile/age/blob/main/logo/logo_white.svg">
        <source media="(prefers-color-scheme: light)" srcset="https://github.com/FiloSottile/age/blob/main/logo/logo.svg">
        <img alt="The age logo, an wireframe of St. Peters dome in Rome, with the text: age, file encryption" width="600" src="https://github.com/FiloSottile/age/blob/main/logo/logo.svg">
    </picture>
</p>

[`age-encryption`](https://www.npmjs.com/package/age-encryption) is a TypeScript
implementation of the [age](https://age-encryption.org) file encryption format.

It depends only on the [noble](https://paulmillr.com/noble/) cryptography
libraries, and uses the Web Crypto API when available.

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

### ASCII armoring

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

### Web Crypto identities

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
