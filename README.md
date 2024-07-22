<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://github.com/FiloSottile/age/blob/main/logo/logo_white.svg">
        <source media="(prefers-color-scheme: light)" srcset="https://github.com/FiloSottile/age/blob/main/logo/logo.svg">
        <img alt="The age logo, an wireframe of St. Peters dome in Rome, with the text: age, file encryption" width="600" src="https://github.com/FiloSottile/age/blob/main/logo/logo.svg">
    </picture>
</p>

[`age-encryption`](https://www.npmjs.com/package/age-encryption) is a TypeScript implementation of the
[age](https://age-encryption.org) file encryption format.

## Installation

```sh
npm install age-encryption
```

## Usage

`age-encryption` is a modern ES Module, compatible with Node.js and Bun, with built-in types.

#### Encrypt and decrypt a file with a new recipient / identity pair

```ts
import * as age from "age-encryption"

const identity = age.generateIdentity()
const recipient = age.identityToRecipient(identity)
console.log(identity)
console.log(recipient)

const e = new age.Encrypter()
e.addRecipient(recipient)
const ciphertext = e.encrypt("Hello, age!")

const d = new age.Decrypter()
d.addIdentity(identity)
const out = d.decrypt(ciphertext, "text")
console.log(out)
```

#### Encrypt and decrypt a file with a passphrase

```ts
import { Encrypter, Decrypter } from "age-encryption"

const e = new Encrypter()
e.setPassphrase("burst-swarm-slender-curve-ability-various-crystal-moon-affair-three")
const ciphertext = e.encrypt("Hello, age!")

const d = new Decrypter()
d.addPassphrase("burst-swarm-slender-curve-ability-various-crystal-moon-affair-three")
const out = d.decrypt(ciphertext, "text")
console.log(out)
```

### Browser usage

`age-encryption` is compatible with modern bundlers such as [esbuild](https://esbuild.github.io/).

To produce a classic library file that sets `age` as a global variable, you can run

```sh
cd "$(mktemp -d)" && npm init -y && npm install esbuild age-encryption
npx esbuild --target=es6 --bundle --minify --outfile=age.js --global-name=age age-encryption
```

<-- TODO: why doesn't

  npx --package esbuild --package age-encryption -- esbuild ...

work? It should run esbuild in an environment where age-encryption is available. -->

Then, you can use it like this

```html
<script src="age.js"></script>
<script>
    const identity = age.generateIdentity()
    const recipient = age.identityToRecipient(identity)
    console.log(identity)
    console.log(recipient)

    const e = new age.Encrypter()
    e.addRecipient(recipient)
    const ciphertext = e.encrypt("Hello, age!")

    const d = new age.Decrypter()
    d.addIdentity(identity)
    const out = d.decrypt(ciphertext, "text")
    console.log(out)
</script>
```
