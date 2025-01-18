[**age-encryption**](../README.md)

***

[age-encryption](../README.md) / generateIdentity

# Function: generateIdentity()

> **generateIdentity**(): `Promise`\<`string`\>

Defined in: [recipients.ts:19](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/recipients.ts#L19)

Generate a new native age identity.

## Returns

`Promise`\<`string`\>

A promise that resolves to the new identity, a string starting with
`AGE-SECRET-KEY-1...`. Use [identityToRecipient](identityToRecipient.md) to produce the
corresponding recipient.
