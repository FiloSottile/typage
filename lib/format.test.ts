import { strict as assert } from 'assert'
import { from_string } from 'libsodium-wrappers-sumo'
import { decodeBase64, parseHeader } from './format'

const exampleHeader = `age-encryption.org/v1
-> X25519 abc
0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM
this is the payload`

describe('parseHeader', () => {
    it('should parse a well formatted header', () => {
        const h = parseHeader(from_string(exampleHeader))
        assert.equal(h.recipients.length, 1)
        assert.deepEqual(h.recipients[0].args, ["X25519", "abc"])
        assert.deepEqual(h.recipients[0].body, decodeBase64("0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE"))
        assert.deepEqual(h.MAC, decodeBase64("gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM"))
        assert.deepEqual(h.rest, from_string("this is the payload"))
    })
})

describe('decodeBase64', () => {
    it('should parse a valid base64 string', () => {
        assert.deepEqual(decodeBase64("dGVzdA"), from_string("test"))
    })
    it('should parse a valid base64 string with spare bits', () => {
        assert.deepEqual(decodeBase64("dGVzdDI"), from_string("test2"))
    })
    it('should reject a non-canonical base64 string', () => {
        assert.throws(() => { decodeBase64("dGVzdDJ") })
    })
    it('should reject a base64 string with padding', () => {
        assert.throws(() => { decodeBase64("dGVzdDI=") })
    })
})
