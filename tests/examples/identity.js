import * as age from "age-encryption"

const identity = await age.generateIdentity()
const recipient = await age.identityToRecipient(identity)
console.log(identity)
console.log(recipient)

const e = new age.Encrypter()
e.addRecipient(recipient)
const ciphertext = await e.encrypt("Hello, age!")
const armored = age.armor.encode(ciphertext)
console.log(armored)

const d = new age.Decrypter()
d.addIdentity(identity)
const decoded = age.armor.decode(armored)
const out = await d.decrypt(decoded, "text")
console.log(out)
