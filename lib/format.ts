import { base64nopad } from "@scure/base"

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

class ByteReader {
    private s: ReadableStreamDefaultReader<Uint8Array>
    private transcript: Uint8Array[] = []
    private buf: Uint8Array

    constructor(stream: ReadableStream<Uint8Array>, prefix: Uint8Array = new Uint8Array()) {
        this.s = stream.getReader()
        this.buf = prefix
    }

    async readLine(): Promise<string | null> {
        const line: Uint8Array[] = []
        while (true) {
            const i = this.buf.indexOf("\n".charCodeAt(0))
            if (i >= 0) {
                line.push(this.buf.subarray(0, i))
                this.transcript.push(this.buf.subarray(0, i + 1))
                this.buf = this.buf.subarray(i + 1)
                return asciiString(flattenArray(line))
            }
            if (this.buf.length > 0) {
                line.push(this.buf)
                this.transcript.push(this.buf)
            }

            const next = await this.s.read()
            if (next.done) {
                this.buf = flattenArray(line)
                return null
            }
            this.buf = next.value
        }
    }

    close(): { rest: Uint8Array, transcript: Uint8Array } {
        this.s.releaseLock()
        return { rest: this.buf, transcript: flattenArray(this.transcript) }
    }
}

async function parseNextStanza(hdr: ByteReader): Promise<{ s: Stanza, next?: never } | { s?: never, next: string }> {
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
    const body = flattenArray(bodyLines)

    return { s: new Stanza(args, body) }
}

function flattenArray(arr: Uint8Array[]): Uint8Array {
    const len = arr.reduce(((sum, line) => sum + line.length), 0)
    const out = new Uint8Array(len)
    let n = 0
    for (const a of arr) {
        out.set(a, n)
        n += a.length
    }
    return out
}

function asciiString(bytes: Uint8Array): string {
    bytes.forEach((b) => {
        if (b < 32 || b > 126) {
            throw Error("invalid non-ASCII byte in header")
        }
    })
    return new TextDecoder().decode(bytes)
}

function prependToStream(prefix: Uint8Array, s: ReadableStream<Uint8Array>): ReadableStream<Uint8Array> {
    const reader = s.getReader()
    return new ReadableStream({
        start(controller) {
            controller.enqueue(prefix)
        },
        async pull(controller) {
            const { done, value } = await reader.read()
            if (done) {
                controller.close()
                return
            }
            controller.enqueue(value)
        },
        cancel(reason) {
            return s.cancel(reason)
        },
    })
}

export async function parseHeader(header: ReadableStream<Uint8Array>): Promise<{
    stanzas: Stanza[], MAC: Uint8Array, headerNoMAC: Uint8Array, rest: ReadableStream<Uint8Array>,
}> {
    const hdr = new ByteReader(header)
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
        return { stanzas, headerNoMAC, MAC, rest: prependToStream(rest, header) }
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
    return flattenArray([
        encodeHeaderNoMAC(recipients),
        new TextEncoder().encode(" " + base64nopad.encode(MAC) + "\n")
    ])
}
