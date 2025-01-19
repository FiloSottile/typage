import { base64 } from "@scure/base"
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import { type Encrypter, type Decrypter } from "./index.js"

/**
 * Encode an age encrypted file using the ASCII armor format, a strict subset of
 * PEM that starts with `-----BEGIN AGE ENCRYPTED FILE-----`.
 *
 * @param file - The raw encrypted file (returned by {@link Encrypter.encrypt}).
 *
 * @returns The ASCII armored file, with a final newline.
 */
export function encode(file: Uint8Array): string {
    const lines: string[] = []
    lines.push("-----BEGIN AGE ENCRYPTED FILE-----\n")
    for (let i = 0; i < file.length; i += 48) {
        let end = i + 48
        if (end > file.length) end = file.length
        lines.push(base64.encode(file.subarray(i, end)) + "\n")
    }
    lines.push("-----END AGE ENCRYPTED FILE-----\n")
    return lines.join("")
}

/**
 * Decode an age encrypted file from the ASCII armor format, a strict subset of
 * PEM that starts with `-----BEGIN AGE ENCRYPTED FILE-----`.
 *
 * Extra whitespace before and after the file is ignored, and newlines can be
 * CRLF or LF, but otherwise the format is parsed strictly.
 *
 * @param file - The ASCII armored file.
 *
 * @returns The raw encrypted file (to be passed to {@link Decrypter.decrypt}).
 */
export function decode(file: string): Uint8Array {
    const lines = file.trim().replaceAll("\r\n", "\n").split("\n")
    if (lines[0] !== "-----BEGIN AGE ENCRYPTED FILE-----") {
        throw Error("invalid header")
    }
    if (lines[lines.length - 1] !== "-----END AGE ENCRYPTED FILE-----") {
        throw Error("invalid footer")
    }
    lines.shift()
    lines.pop()
    if (lines.some((l, i) => i === lines.length - 1 ? l.length > 64 : l.length !== 64)) {
        throw Error("line too long")
    }
    return base64.decode(lines.join(""))
}
