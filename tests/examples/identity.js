import { Encrypter, Decrypter, generateIdentity, identityToRecipient } from "age-encryption"

const identity = await generateIdentity()
const recipient = await identityToRecipient(identity)
console.log(identity)
console.log(recipient)

const e = new Encrypter()
e.addRecipient(recipient)
const ciphertext = await e.encrypt("Hello, age!")

const d = new Decrypter()
d.addIdentity(identity)
const out = await d.decrypt(ciphertext, "text")
console.log(out)
