import { strict as assert } from 'assert'
import { from_string, to_hex } from 'libsodium-wrappers-sumo'
import { HKDF } from './hkdf'

describe('HKDF', () => {
    it('should generate the right value for secret/salt/info', () => {
        const h = HKDF(from_string("saltsaltsaltsaltsaltsaltsaltsalt"), "info", from_string("secret"))
        assert.equal(to_hex(h), "b3bae2c60b0fffa7c7eb7af6560f6419b027feb579f42674c7b6ef6fbca64d7d")
    })
    it('should generate the right value for null salt', () => {
        const h = HKDF(null, "info", from_string("secret"))
        assert.equal(to_hex(h), "7e11a191fa879919dcf4e336e0d736091bee42c78d4ccb86214290a677884a7a")
    })
})
