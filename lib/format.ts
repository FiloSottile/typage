import { base64nopad } from "@scure/base"
import { LineReader, flatten, prepend } from "./io.js"

/**
 * A stanza is a section of an age header. This is part of the low-level
 * {@link Recipient} and {@link Identity} APIs.
 */
export class Stanza {
    /**
     * All space-separated arguments on the first line of the stanza.
     * Each argument is a string that does not contain spaces.
     * The first argument is often a recipient type, which should look like
     * `example.com/...` to avoid collisions.
     */
    readonly args: string[]
    /**
     * The raw body of the stanza. This is automatically base64-encoded and
     * split into lines of 48 characters each.
     */
    readonly body: Uint8Array

    constructor(args: string[], body: Uint8Array) {
        this.args = args
        this.body = body
    }
}

async function parseNextStanza(hdr: LineReader): Promise<{ s: Stanza, next?: never } | { s?: never, next: string }> {
    const argsLine = await hdr.readLine()
    if (argsLine === null) {
        throw Error("invalid stanza")
    }
    const args = argsLine.split(" ")
    if (args.length < 2 || args.shift() !== "->") {
        return { next: argsLine }
    }
    for (const arg of args) {
        if (arg.length === 0) {
            throw Error("invalid stanza")
        }
    }

    const bodyLines: Uint8Array[] = []
    for (; ;) {
        const nextLine = await hdr.readLine()
        if (nextLine === null) {
            throw Error("invalid stanza")
        }
        const line = base64nopad.decode(nextLine)
        if (line.length > 48) {
            throw Error("invalid stanza")
        }
        bodyLines.push(line)
        if (line.length < 48) {
            break
        }
    }
    const body = flatten(bodyLines)

    return { s: new Stanza(args, body) }
}

export async function parseHeader(header: ReadableStream<Uint8Array>): Promise<{
    stanzas: Stanza[], MAC: Uint8Array, headerNoMAC: Uint8Array, rest: ReadableStream<Uint8Array>,
}> {
    const hdr = new LineReader(header)
    const versionLine = await hdr.readLine()
    if (versionLine !== "age-encryption.org/v1") {
        throw Error("invalid version " + (versionLine ?? "line"))
    }

    const stanzas: Stanza[] = []
    for (; ;) {
        const { s, next: macLine } = await parseNextStanza(hdr)
        if (s !== undefined) {
            stanzas.push(s)
            continue
        }

        if (!macLine.startsWith("--- ")) {
            throw Error("invalid header")
        }
        const MAC = base64nopad.decode(macLine.slice(4))
        const { rest, transcript } = hdr.close()
        const headerNoMAC = transcript.slice(0, transcript.length - 1 - macLine.length + 3)
        return { stanzas, headerNoMAC, MAC, rest: prepend(header, rest) }
    }
}

export function encodeHeaderNoMAC(recipients: Stanza[]): Uint8Array {
    const lines: string[] = []
    lines.push("age-encryption.org/v1\n")

    for (const s of recipients) {
        lines.push("-> " + s.args.join(" ") + "\n")
        for (let i = 0; i < s.body.length; i += 48) {
            let end = i + 48
            if (end > s.body.length) end = s.body.length
            lines.push(base64nopad.encode(s.body.subarray(i, end)) + "\n")
        }
        if (s.body.length % 48 === 0) lines.push("\n")
    }

    lines.push("---")
    return new TextEncoder().encode(lines.join(""))
}

export function encodeHeader(recipients: Stanza[], MAC: Uint8Array): Uint8Array {
    return flatten([
        encodeHeaderNoMAC(recipients),
        new TextEncoder().encode(" " + base64nopad.encode(MAC) + "\n")
    ])
}
