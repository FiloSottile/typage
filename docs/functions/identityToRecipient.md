[**age-encryption**](../README.md)

***

[age-encryption](../README.md) / identityToRecipient

# Function: identityToRecipient()

> **identityToRecipient**(`identity`): `Promise`\<`string`\>

Defined in: [recipients.ts:39](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/recipients.ts#L39)

Convert an age identity to a recipient.

## Parameters

### identity

An age identity, a string starting with
`AGE-SECRET-KEY-1...` or an X25519 private
[CryptoKey](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey)
object.

`string` | `CryptoKey`

## Returns

`Promise`\<`string`\>

A promise that resolves to the corresponding recipient, a string
starting with `age1...`.

## See

 - [generateIdentity](generateIdentity.md)
 - [Decrypter.addIdentity](../classes/Decrypter.md#addidentity)
