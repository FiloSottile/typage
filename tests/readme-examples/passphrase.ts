#!/usr/bin/env bun

import age from "../../lib/index.js";

// Initialize the library (calls sodium.ready).

const { Encrypter, Decrypter, generateIdentity, identityToRecipient } = await age()

// Encrypt and decrypt a file with a passphrase.

const e = new Encrypter()
e.setPassphrase("burst-swarm-slender-curve-ability-various-crystal-moon-affair-three")
const ciphertext = e.encrypt("Hello, age!")

const d = new Decrypter()
d.addPassphrase("burst-swarm-slender-curve-ability-various-crystal-moon-affair-three")
const out = d.decrypt(ciphertext, "text")
console.log(out)
