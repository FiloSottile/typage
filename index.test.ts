import { strict as assert } from 'assert'
import { base64_variants, from_base64, to_string } from "libsodium-wrappers-sumo"
import { AgeDecrypter } from "."

const fromBase64 = (s: string) => from_base64(s, base64_variants.ORIGINAL_NO_PADDING)

describe('AgeDecrypter', function () {
    it('should decrypt a file with the right passphrase', async function () {
        this.timeout(5000)
        const d = new AgeDecrypter()
        d.addPassphrase("light-original-energy-average-wish-blind-vendor-pencil-illness-scorpion")
        const file = fromBase64("YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBtRld1R1VqUGxQM25ZdCtIOU03WHN3IDE4CkRnRWRIVnF0N0pZNGg0cWJaMmJKRzdteS9mNHhhR1lqUVo4MkR3WWR4NVEKLS0tIDQ5bmRwY1hRN2kvc0I0VndlUzg3V2tiWGFLY1dzcENkVzFDZnBHWlZMWVEK1txQDiJz/J97zMFjZX/tDp10RCfFgBYd4Tt17tfaNfsZaR5E+A")
        assert.deepEqual(to_string(await d.decrypt(file)), "test\n")
    })
})
