import { strict as assert } from 'assert'
import { base64_variants, from_base64, from_string } from 'libsodium-wrappers-sumo'
import { parseHeader } from './format'

const exampleHeader = `age-encryption.org/v1
-> X25519 abc
0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM
this is the payload`

const fromBase64 = (s: string) => from_base64(s, base64_variants.ORIGINAL_NO_PADDING)

describe('parseHeader', () => {
    it('should parse a well formatted header', () => {
        const h = parseHeader(from_string(exampleHeader))
        assert.equal(h.recipients.length, 1)
        assert.deepEqual(h.recipients[0].args, ["X25519", "abc"])
        assert.deepEqual(h.recipients[0].body, fromBase64("0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE"))
        assert.deepEqual(h.MAC, fromBase64("gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM"))
        assert.deepEqual(h.rest, from_string("this is the payload"))
    })
})
