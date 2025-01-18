[**age-encryption**](../README.md)

***

[age-encryption](../README.md) / Recipient

# Interface: Recipient

Defined in: [index.ts:47](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/index.ts#L47)

A recipient that can be used to encrypt a file key.

This is a low-level interface that can be used to implement custom recipient
types. Most users won't need to interact with this directly, and should
instead pass a string encoding of a standard recipient (`age1...`) to
[Encrypter.addRecipient](../classes/Encrypter.md#addrecipient).

## Methods

### wrapFileKey()

> **wrapFileKey**(`fileKey`): [`Stanza`](../classes/Stanza.md)[] \| `Promise`\<[`Stanza`](../classes/Stanza.md)[]\>

Defined in: [index.ts:59](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/index.ts#L59)

Encrypt a file key for this recipient. This function is called during
[Encrypter.encrypt](../classes/Encrypter.md#encrypt), once for each file.

#### Parameters

##### fileKey

`Uint8Array`

The random file key to encrypt.

#### Returns

[`Stanza`](../classes/Stanza.md)[] \| `Promise`\<[`Stanza`](../classes/Stanza.md)[]\>

One or more stanzas that will be included (unencrypted) in the
encrypted file's header. The corresponding identity (which may be the
built-in X25519 or scrypt identity, or a custom [Identity](Identity.md)) must be
able to identify these stanzas, and use them to decrypt the file key.
