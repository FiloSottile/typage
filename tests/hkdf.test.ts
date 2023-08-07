import { strict as assert } from 'assert'
import { from_string, to_hex } from 'libsodium-wrappers-sumo'
import { HKDF } from '../lib/hkdf.js'

describe('HKDF', () => {
    it('should generate the right value for secret/salt/info', () => {
        const h = HKDF(from_string("secret"), from_string("saltsaltsaltsaltsaltsaltsaltsalt"), "info")
        assert.equal(to_hex(h), "b3bae2c60b0fffa7c7eb7af6560f6419b027feb579f42674c7b6ef6fbca64d7d")
    })
    it('should generate the right value for short salt', () => {
        const h = HKDF(from_string("secret"), from_string("salt"), "info")
        assert.equal(to_hex(h), "f6d2fcc47cb939deafe3853a1e641a27e6924aff7a63d09cb04ccfffbe4776ef")
    })
    it('should generate the right value for null salt', () => {
        const h = HKDF(from_string("secret"), null, "info")
        assert.equal(to_hex(h), "7e11a191fa879919dcf4e336e0d736091bee42c78d4ccb86214290a677884a7a")
    })
})
