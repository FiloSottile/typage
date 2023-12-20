import { Encrypter, Decrypter } from "age-encryption"

const e = new Encrypter()
e.setScryptWorkFactor(12) // this is NOT secure, used to avoid extra work in tests
e.setPassphrase("burst-swarm-slender-curve-ability-various-crystal-moon-affair-three")
const ciphertext = e.encrypt("Hello, age!")

const d = new Decrypter()
d.addPassphrase("burst-swarm-slender-curve-ability-various-crystal-moon-affair-three")
const out = d.decrypt(ciphertext, "text")
console.log(out)
