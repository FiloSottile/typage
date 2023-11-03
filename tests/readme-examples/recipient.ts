#!/usr/bin/env bun

import age from "../../lib/index.js";

// Initialize the library (calls sodium.ready).

const { Encrypter, Decrypter, generateIdentity, identityToRecipient } = await age()

// Encrypt and decrypt a file with a new recipient / identity pair.

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
