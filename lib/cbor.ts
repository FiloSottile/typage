// This file implements a tiny subset of CTAP2's subset of CBOR, in order to
// encode and decode WebAuthn identities.
//
// Only major types 0 (unsigned integer), 2 (byte strings), 3 (text strings),
// and 4 (arrays, only containing text strings) are supported. Arguments are
// limited to 16-bit values.
//
// See https://www.imperialviolet.org/tourofwebauthn/tourofwebauthn.html#cbor.

function readTypeAndArgument(b: Uint8Array): [number, number, Uint8Array] {
    if (b.length === 0) {
        throw Error("cbor: unexpected EOF")
    }
    const major = b[0] >> 5
    const minor = b[0] & 0x1f
    if (minor <= 23) {
        return [major, minor, b.subarray(1)]
    }
    if (minor === 24) {
        if (b.length < 2) {
            throw Error("cbor: unexpected EOF")
        }
        return [major, b[1], b.subarray(2)]
    }
    if (minor === 25) {
        if (b.length < 3) {
            throw Error("cbor: unexpected EOF")
        }
        return [major, (b[1] << 8) | b[2], b.subarray(3)]
    }
    throw Error("cbor: unsupported argument encoding")
}

export function readUint(b: Uint8Array): [number, Uint8Array] {
    const [major, minor, rest] = readTypeAndArgument(b)
    if (major !== 0) {
        throw Error("cbor: expected unsigned integer")
    }
    return [minor, rest]
}

export function readByteString(b: Uint8Array): [Uint8Array, Uint8Array] {
    const [major, minor, rest] = readTypeAndArgument(b)
    if (major !== 2) {
        throw Error("cbor: expected byte string")
    }
    if (minor > rest.length) {
        throw Error("cbor: unexpected EOF")
    }
    return [rest.subarray(0, minor), rest.subarray(minor)]
}

export function readTextString(b: Uint8Array): [string, Uint8Array] {
    const [major, minor, rest] = readTypeAndArgument(b)
    if (major !== 3) {
        throw Error("cbor: expected text string")
    }
    if (minor > rest.length) {
        throw Error("cbor: unexpected EOF")
    }
    return [new TextDecoder().decode(rest.subarray(0, minor)), rest.subarray(minor)]
}

export function readArray(b: Uint8Array): [string[], Uint8Array] {
    const [major, minor, r] = readTypeAndArgument(b)
    if (major !== 4) {
        throw Error("cbor: expected array")
    }
    let rest = r
    const args = []
    for (let i = 0; i < minor; i++) {
        let arg
        [arg, rest] = readTextString(rest)
        args.push(arg)
    }
    return [args, rest]
}

export function encodeUint(n: number): Uint8Array {
    if (n <= 23) {
        return new Uint8Array([n])
    }
    if (n <= 0xff) {
        return new Uint8Array([24, n])
    }
    if (n <= 0xffff) {
        return new Uint8Array([25, n >> 8, n & 0xff])
    }
    throw Error("cbor: unsigned integer too large")
}

export function encodeByteString(b: Uint8Array): Uint8Array {
    if (b.length <= 23) {
        return new Uint8Array([2 << 5 | b.length, ...b])
    }
    if (b.length <= 0xff) {
        return new Uint8Array([2 << 5 | 24, b.length, ...b])
    }
    if (b.length <= 0xffff) {
        return new Uint8Array([2 << 5 | 25, b.length >> 8, b.length & 0xff, ...b])
    }
    throw Error("cbor: byte string too long")
}

export function encodeTextString(s: string): Uint8Array {
    const b = new TextEncoder().encode(s)
    if (b.length <= 23) {
        return new Uint8Array([3 << 5 | b.length, ...b])
    }
    if (b.length <= 0xff) {
        return new Uint8Array([3 << 5 | 24, b.length, ...b])
    }
    if (b.length <= 0xffff) {
        return new Uint8Array([3 << 5 | 25, b.length >> 8, b.length & 0xff, ...b])
    }
    throw Error("cbor: text string too long")
}

export function encodeArray(args: string[]): Uint8Array {
    const body = args.flatMap(x => [...encodeTextString(x)])
    if (args.length <= 23) {
        return new Uint8Array([4 << 5 | args.length, ...body])
    }
    if (args.length <= 0xff) {
        return new Uint8Array([4 << 5 | 24, args.length, ...body])
    }
    if (args.length <= 0xffff) {
        return new Uint8Array([4 << 5 | 25, args.length >> 8, args.length & 0xff, ...body])
    }
    throw Error("cbor: array too long")
}
