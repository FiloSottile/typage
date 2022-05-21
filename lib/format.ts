import { base64_variants, from_base64, to_string } from "libsodium-wrappers-sumo"

export const decodeBase64 = (s: string) => from_base64(s, base64_variants.ORIGINAL_NO_PADDING)

export class Stanza {
    readonly args: string[]
    readonly body: Uint8Array

    constructor(args: string[], body: Uint8Array) {
        this.args = args
        this.body = body
    }
}

class ByteReader {
    private arr: Uint8Array
    constructor(arr: Uint8Array) {
        this.arr = arr
    }

    private toString(bytes: Uint8Array): string {
        bytes.forEach((b) => {
            if (b < 32 || b > 136) {
                throw Error("invalid non-ASCII byte in header")
            }
        })
        return to_string(bytes)
    }

    readString(n: number): string {
        const out = this.arr.subarray(0, n)
        this.arr = this.arr.subarray(n)
        return this.toString(out)
    }

    readLine(): string | null {
        const i = this.arr.indexOf('\n'.charCodeAt(0))
        if (i >= 0) {
            const out = this.arr.subarray(0, i)
            this.arr = this.arr.subarray(i + 1)
            return this.toString(out)
        }
        return null
    }

    rest(): Uint8Array {
        return this.arr
    }
}

function parseNextStanza(header: Uint8Array): [s: Stanza, rest: Uint8Array] {
    const hdr = new ByteReader(header)
    if (hdr.readString(3) !== "-> ") {
        throw Error("invalid stanza")
    }

    const argsLine = hdr.readLine()
    if (argsLine === null) {
        throw Error("invalid stanza")
    }
    const args = argsLine.split(" ")
    if (args.length < 1) {
        throw Error("invalid stanza")
    }

    const bodyLines: Uint8Array[] = []
    for (; ;) {
        const nextLine = hdr.readLine()
        if (nextLine === null) {
            throw Error("invalid stanza")
        }
        const line = decodeBase64(nextLine)
        bodyLines.push(line)
        if (line.length < 48) {
            break
        }
    }

    const bodyLen = bodyLines.reduce(((sum, line) => sum + line.length), 0)
    const body = new Uint8Array(bodyLen)
    let n = 0
    for (const line of bodyLines) {
        body.set(line, n)
        n += line.length
    }

    return [new Stanza(args, body), hdr.rest()]
}

export function parseHeader(header: Uint8Array): {
    recipients: Stanza[], MAC: Uint8Array, headerNoMAC: Uint8Array, rest: Uint8Array
} {
    let hdr = new ByteReader(header)
    const versionLine = hdr.readLine()
    if (versionLine !== "age-encryption.org/v1") {
        throw Error("invalid version " + versionLine)
    }
    let rest = hdr.rest()

    const recipients: Stanza[] = []
    for (; ;) {
        let s: Stanza
        [s, rest] = parseNextStanza(rest)
        recipients.push(s)

        hdr = new ByteReader(rest)
        if (hdr.readString(4) === "--- ") {
            const headerNoMAC = header.subarray(0, header.length - hdr.rest().length - 1)
            const macLine = hdr.readLine()
            if (macLine === null) {
                throw Error("invalid header")
            }
            const mac = decodeBase64(macLine)

            return {
                recipients: recipients,
                headerNoMAC: headerNoMAC,
                MAC: mac,
                rest: hdr.rest(),
            }
        }
    }
}
