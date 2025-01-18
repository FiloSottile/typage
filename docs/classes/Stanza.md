[**age-encryption**](../README.md)

***

[age-encryption](../README.md) / Stanza

# Class: Stanza

Defined in: [format.ts:7](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/format.ts#L7)

A stanza is a section of an age header. This is part of the low-level
[Recipient](../interfaces/Recipient.md) and [Identity](../interfaces/Identity.md) APIs.

## Constructors

### new Stanza()

> **new Stanza**(`args`, `body`): [`Stanza`](Stanza.md)

Defined in: [format.ts:21](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/format.ts#L21)

#### Parameters

##### args

`string`[]

##### body

`Uint8Array`

#### Returns

[`Stanza`](Stanza.md)

## Properties

### args

> `readonly` **args**: `string`[]

Defined in: [format.ts:14](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/format.ts#L14)

All space-separated arguments on the first line of the stanza.
Each argument is a string that does not contain spaces.
The first argument is often a recipient type, which should look like
`example.com/...` to avoid collisions.

***

### body

> `readonly` **body**: `Uint8Array`

Defined in: [format.ts:19](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/format.ts#L19)

The raw body of the stanza. This is automatically base64-encoded and
split into lines of 48 characters each.
