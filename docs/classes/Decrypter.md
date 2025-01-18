[**age-encryption**](../README.md)

***

[age-encryption](../README.md) / Decrypter

# Class: Decrypter

Defined in: [index.ts:179](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/index.ts#L179)

Decrypts a file using the given identities.

First, call [Decrypter.addPassphrase](Decrypter.md#addpassphrase) to set a passphrase for symmetric
decryption, and/or [Decrypter.addIdentity](Decrypter.md#addidentity) to specify one or more
identities. All passphrases and/or identities are tried in parallel for each
file. Then, call [Decrypter.decrypt](Decrypter.md#decrypt) one or more times to decrypt files
using the configured passphrase and/or identities.

## Constructors

### new Decrypter()

> **new Decrypter**(): [`Decrypter`](Decrypter.md)

#### Returns

[`Decrypter`](Decrypter.md)

## Methods

### addIdentity()

> **addIdentity**(`s`): `void`

Defined in: [index.ts:213](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/index.ts#L213)

Add an identity to decrypt file(s) with. This method can be called
multiple times to try multiple identities.

#### Parameters

##### s

The identity to decrypt the file with. Either a string
beginning with `AGE-SECRET-KEY-1...`, an X25519 private
[CryptoKey](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey)
object, or an object implementing the [Identity](../interfaces/Identity.md) interface.

A CryptoKey object must have
[type](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/type)
`private`,
[algorithm](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/algorithm)
`{name: 'X25519'}`, and
[usages](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/usages)
`["deriveBits"]`. For example:
```js
const keyPair = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])
decrypter.addIdentity(key.privateKey)
```

`string` | `CryptoKey` | [`Identity`](../interfaces/Identity.md)

#### Returns

`void`

***

### addPassphrase()

> **addPassphrase**(`s`): `void`

Defined in: [index.ts:188](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/index.ts#L188)

Add a passphrase to decrypt password-encrypted file(s) with. This method
can be called multiple times to try multiple passphrases.

#### Parameters

##### s

`string`

The passphrase to decrypt the file with.

#### Returns

`void`

***

### decrypt()

#### Call Signature

> **decrypt**(`file`, `outputFormat`?): `Promise`\<`Uint8Array`\>

Defined in: [index.ts:231](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/index.ts#L231)

Decrypt a file using the configured passphrases and/or identities.

##### Parameters

###### file

`Uint8Array`

The file to decrypt.

###### outputFormat?

`"uint8array"`

The format to return the decrypted file in. If
`"text"` is passed, the file's plaintext will be decoded as UTF-8 and
returned as a string. Optional. It defaults to `"uint8array"`.

##### Returns

`Promise`\<`Uint8Array`\>

A promise that resolves to the decrypted file.

#### Call Signature

> **decrypt**(`file`, `outputFormat`): `Promise`\<`string`\>

Defined in: [index.ts:232](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/index.ts#L232)

Decrypt a file using the configured passphrases and/or identities.

##### Parameters

###### file

`Uint8Array`

The file to decrypt.

###### outputFormat

`"text"`

The format to return the decrypted file in. If
`"text"` is passed, the file's plaintext will be decoded as UTF-8 and
returned as a string. Optional. It defaults to `"uint8array"`.

##### Returns

`Promise`\<`string`\>

A promise that resolves to the decrypted file.
