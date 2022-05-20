import { strict as assert } from 'assert'
import { base64_variants, from_base64, to_string } from "libsodium-wrappers-sumo"
import { AgeDecrypter } from "."

const fromBase64 = (s: string) => from_base64(s, base64_variants.ORIGINAL_NO_PADDING)

describe('AgeDecrypter', function () {
    it('should decrypt a file with the right passphrase', async function () {
        const d = new AgeDecrypter()
        d.addPassphrase("light-original-energy-average-wish-blind-vendor-pencil-illness-scorpion")
        const file = fromBase64("YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4Y2lkcXJQdmwwZzRROEZ5eXU4dHNnIDgKNnM2Ylp2Vlg2b0NBSVp2QkxCZEhJbEJrYUcreWRIZHVHWVpBaUJkUy9ZMAotLS0gZ280TkNGT05VTDEwZW5WRjVPMnkxem05eWQwdkM0S09hSU1nV05aYW5QSQom4WH7RYXsjlDm3HNKCe9gY2IfCjTY/2t6PF4bzUkeWZWkE7kd")
        assert.deepEqual(to_string(await d.decrypt(file)), "test\n")
    })

    it('should decrypt a file with the right identity', async function () {
        const d = new AgeDecrypter()
        d.addIdentity("AGE-SECRET-KEY-1L27NYJDYRNDSCCELNZE8C6JTSH22TLQJVPGD7289KDLMZA5HWN6SZPEHGF")
        const file = fromBase64("YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBOb280UHUyVWZwTllzY3Z5OU1tTjlscHV1Smt4Nng0MEZkdGZoQzd1dVFZCmk0VUNvVmoxbEhHalV0bVR2MHFyRGl0YzNtMXdoY1oyVUtvWDU3MUQwR1EKLS0tIGJ1RTZSYmR6ZlNHSk5tSGl3U2hqR1FFUDF4eEdjSGZtbXlYQUN4SnM4RDAKyqdZXpg65sTtmakjxLONtEgaSwXeS8t+7jAWvlleVEFO4/9QIQ")
        assert.deepEqual(to_string(await d.decrypt(file)), "test\n")
    })
})
