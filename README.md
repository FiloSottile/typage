<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://github.com/FiloSottile/age/blob/main/logo/logo_white.svg">
        <source media="(prefers-color-scheme: light)" srcset="https://github.com/FiloSottile/age/blob/main/logo/logo.svg">
        <img alt="The age logo, an wireframe of St. Peters dome in Rome, with the text: age, file encryption" width="600" src="https://github.com/FiloSottile/age/blob/main/logo/logo.svg">
    </picture>
</p>

[`age-encryption`](https://www.npmjs.com/package/age-encryption) is a TypeScript implementation of the
[age](https://age-encryption.org) file encryption format.

All low-level cryptographic operations are implemented with [libsodium.js](https://github.com/jedisct1/libsodium.js).

## Installation

```sh
npm install age-encryption
```

## Usage

`age-encryption` is a modern ES Module, compatible with Node.js and Bun, with built-in types.

There is a single exported function, `age()`, which returns a Promise that resolves to an object that provides the package API. This is necessary to ensure that applications always call `sodium.ready()` from libsodium.js.

#### Encrypt and decrypt a file with a new recipient / identity pair

```ts
import age from "age-encryption"

// Initialize the age library (calls sodium.ready).
const { Encrypter, Decrypter, generateIdentity, identityToRecipient } = await age()

const identity = generateIdentity()
const recipient = identityToRecipient(identity)
console.log(identity)
console.log(recipient)

const e = new Encrypter()
e.addRecipient(recipient)
const ciphertext = e.encrypt("Hello, age!")

const d = new Decrypter()
d.addIdentity(identity)
const out = d.decrypt(ciphertext, "text")
console.log(out)
```

#### Encrypt and decrypt a file with a passphrase

```ts
import age from "age-encryption"

// Initialize the age library (calls sodium.ready).
const { Encrypter, Decrypter } = await age()

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

To produce a classic library file that sets `age()` as a global variable, you can run

```sh
cd "$(mktemp -d)" && npm init -y && npm install esbuild age-encryption
echo 'import age from "age-encryption"; globalThis.age = age' | \
  npx esbuild --target=es6 --bundle --minify --outfile=age.js
```

Then, you can use it like this

```html
<script src="age.js"></script>
<script>
    age().then((age) => {
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
    })
</script>
```

(Or, in a `script` with `type="module"`, you can use the top-level `await` syntax like in the examples above.)
