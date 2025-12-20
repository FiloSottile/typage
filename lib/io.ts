import { randomBytes } from "@noble/hashes/utils.js"

export class LineReader {
    private s: ReadableStreamDefaultReader<Uint8Array>
    private transcript: Uint8Array[] = []
    private buf: Uint8Array = new Uint8Array(0)

    constructor(stream: ReadableStream<Uint8Array>) {
        this.s = stream.getReader()
    }

    async readLine(): Promise<string | null> {
        const line: Uint8Array[] = []
        while (true) {
            const i = this.buf.indexOf("\n".charCodeAt(0))
            if (i >= 0) {
                line.push(this.buf.subarray(0, i))
                this.transcript.push(this.buf.subarray(0, i + 1))
                this.buf = this.buf.subarray(i + 1)
                return asciiString(flatten(line))
            }
            if (this.buf.length > 0) {
                line.push(this.buf)
                this.transcript.push(this.buf)
            }

            const next = await this.s.read()
            if (next.done) {
                this.buf = flatten(line)
                return null
            }
            this.buf = next.value
        }
    }

    close(): { rest: Uint8Array, transcript: Uint8Array } {
        this.s.releaseLock()
        return { rest: this.buf, transcript: flatten(this.transcript) }
    }
}

function asciiString(bytes: Uint8Array): string {
    bytes.forEach((b) => {
        if (b < 32 || b > 126) {
            throw Error("invalid non-ASCII byte in header")
        }
    })
    return new TextDecoder().decode(bytes)
}

export function flatten(arr: Uint8Array[]): Uint8Array {
    const len = arr.reduce(((sum, line) => sum + line.length), 0)
    const out = new Uint8Array(len)
    let n = 0
    for (const a of arr) {
        out.set(a, n)
        n += a.length
    }
    return out
}

export function prepend(s: ReadableStream<Uint8Array>, ...prefixes: Uint8Array[]): ReadableStream<Uint8Array> {
    return s.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
        start(controller) {
            for (const p of prefixes) {
                controller.enqueue(p)
            }
        }
    }))
}

export function stream(a: Uint8Array): ReadableStream<Uint8Array> {
    // https://developer.mozilla.org/en-US/docs/Web/API/ReadableStream/from_static
    return new ReadableStream({
        start(controller) {
            controller.enqueue(a)
            controller.close()
        }
    })
}

export async function readAll(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
    if (!(stream instanceof ReadableStream)) {
        throw new Error("readAll expects a ReadableStream<Uint8Array>")
    }
    return new Uint8Array(await new Response(stream).arrayBuffer())
}

export async function readAllString(stream: ReadableStream): Promise<string> {
    if (!(stream instanceof ReadableStream)) {
        throw new Error("readAllString expects a ReadableStream<Uint8Array>")
    }
    return await new Response(stream).text()
}

export async function read(stream: ReadableStream<Uint8Array>, n: number): Promise<{ data: Uint8Array, rest: ReadableStream<Uint8Array> }> {
    const reader = stream.getReader()
    const chunks: Uint8Array[] = []
    let readBytes = 0

    while (readBytes < n) {
        const { done, value } = await reader.read()
        if (done) {
            throw Error("stream ended before reading " + n.toString() + " bytes")
        }
        chunks.push(value)
        readBytes += value.length
    }
    reader.releaseLock()

    const buf = flatten(chunks)
    const data = buf.subarray(0, n)
    const rest = prepend(stream, buf.subarray(n))

    return { data, rest }
}

export function randomBytesStream(n: number, chunk: number): ReadableStream<Uint8Array> {
    return new ReadableStream({
        start(controller) {
            for (let i = 0; i < n; i += chunk) {
                controller.enqueue(randomBytes(Math.min(chunk, n - i)))
            }
            controller.close()
        }
    })
}
