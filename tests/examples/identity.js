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
