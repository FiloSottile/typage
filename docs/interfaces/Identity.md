[**age-encryption**](../README.md)

***

[age-encryption](../README.md) / Identity

# Interface: Identity

Defined in: [index.ts:19](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/index.ts#L19)

An identity that can be used to decrypt a file key.

This is a low-level interface that can be used to implement custom identity
types, such as plugins or remote APIs and secrets managers. Most users won't
need to interact with this directly, and should instead pass a string encoding
of a standard identity (`AGE-SECRET-KEY-1...`) to [Decrypter.addIdentity](../classes/Decrypter.md#addidentity).

## Methods

### unwrapFileKey()

> **unwrapFileKey**(`stanzas`): `null` \| `Uint8Array` \| `Promise`\<`null` \| `Uint8Array`\>

Defined in: [index.ts:36](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/index.ts#L36)

Decrypt a file key, if possible, using this identity. This function is
called during [Decrypter.decrypt](../classes/Decrypter.md#decrypt), once for each file.

#### Parameters

##### stanzas

[`Stanza`](../classes/Stanza.md)[]

All stanzas from the encrypted file's header. It is the
identity's responsibility to identify the stanzas it's expecting, if any.

#### Returns

`null` \| `Uint8Array` \| `Promise`\<`null` \| `Uint8Array`\>

The random file key, if this identity can decrypt it, or `null`
if none of the stanzas matched this identity.

#### Throws

`unwrapFileKey` must throw only if it identifies a stanza that
matches this identity, but the stanza is malformed or invalid, or
decryption fails due to external factors (e.g. network errors). For
example, it must return `null`, not throw, if the file is encrypted with
a different e.g. key.
