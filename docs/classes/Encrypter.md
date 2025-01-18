[**age-encryption**](../README.md)

***

[age-encryption](../README.md) / Encrypter

# Class: Encrypter

Defined in: [index.ts:72](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/index.ts#L72)

Encrypts a file using the given passphrase or recipients.

First, call [Encrypter.setPassphrase](Encrypter.md#setpassphrase) to set a passphrase for symmetric
encryption, or [Encrypter.addRecipient](Encrypter.md#addrecipient) to specify one or more
recipients. Then, call [Encrypter.encrypt](Encrypter.md#encrypt) one or more times to encrypt
files using the configured passphrase or recipients.

## Constructors

### new Encrypter()

> **new Encrypter**(): [`Encrypter`](Encrypter.md)

#### Returns

[`Encrypter`](Encrypter.md)

## Methods

### addRecipient()

> **addRecipient**(`s`): `void`

Defined in: [index.ts:118](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/index.ts#L118)

Add a recipient to encrypt the file(s) for. This method can be called
multiple times to encrypt the file(s) for multiple recipients.

#### Parameters

##### s

The recipient to encrypt the file for. Either a string
beginning with `age1...` or an object implementing the [Recipient](../interfaces/Recipient.md)
interface.

`string` | [`Recipient`](../interfaces/Recipient.md)

#### Returns

`void`

***

### encrypt()

> **encrypt**(`file`): `Promise`\<`Uint8Array`\>

Defined in: [index.ts:138](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/index.ts#L138)

Encrypt a file using the configured passphrase or recipients.

#### Parameters

##### file

The file to encrypt. If a string is passed, it will be
encoded as UTF-8.

`string` | `Uint8Array`

#### Returns

`Promise`\<`Uint8Array`\>

A promise that resolves to the encrypted file as a Uint8Array.

***

### setPassphrase()

> **setPassphrase**(`s`): `void`

Defined in: [index.ts:89](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/index.ts#L89)

Set the passphrase to encrypt the file(s) with. This method can only be
called once, and can't be called if [Encrypter.addRecipient](Encrypter.md#addrecipient) has
been called.

The passphrase is passed through the scrypt key derivation function, but
it needs to have enough entropy to resist offline brute-force attacks.
You should use at least 8-10 random alphanumeric characters, or 4-5
random words from a list of at least 2000 words.

#### Parameters

##### s

`string`

The passphrase to encrypt the file with.

#### Returns

`void`

***

### setScryptWorkFactor()

> **setScryptWorkFactor**(`logN`): `void`

Defined in: [index.ts:106](https://github.com/FiloSottile/typage/blob/71f68da909e30220d568bfb648bafe630e17f03c/lib/index.ts#L106)

Set the scrypt work factor to use when encrypting the file(s) with a
passphrase. The default is 18. Using a lower value will require stronger
passphrases to resist offline brute-force attacks.

#### Parameters

##### logN

`number`

The base-2 logarithm of the scrypt work factor.

#### Returns

`void`
