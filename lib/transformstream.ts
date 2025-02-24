import { hmac } from "@noble/hashes/hmac";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import {
  ScryptRecipient,
} from "./recipients.js";
import {
  encodeHeader,
  encodeHeaderNoMAC,
  Stanza,
} from "./format.js";
import { chunkSize } from "./stream.js";
import { Recipient } from "./index.js";
export { generateIdentity, identityToRecipient } from "./recipients.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha";

export class EncrypterTransformer implements Transformer<Uint8Array> {
  private passphrase: string | null = null;
  private scryptWorkFactor = 18;
  private recipients: Recipient[] = [];
  private streamKey: Uint8Array | null = null;
  private streamNonce = new Uint8Array(12);
  private buffer = new Uint8Array(chunkSize);
  private bufferSize = 0;

  constructor({
    passphrase,
    scryptWorkFactor,
    recipients,
  }: {
    passphrase?: string;
    scryptWorkFactor?: number;
    recipients?: Recipient[];
  }) {
    this.passphrase = passphrase === undefined ? null : passphrase;
    this.scryptWorkFactor = scryptWorkFactor === undefined ? 18 : scryptWorkFactor;
    this.recipients = recipients === undefined ? [] : recipients;
  }

  async start(controller: TransformStreamDefaultController) {
    const fileKey = randomBytes(16);
    const stanzas: Stanza[] = [];

    if (this.passphrase !== null) {
      this.recipients = [
        new ScryptRecipient(this.passphrase, this.scryptWorkFactor),
        ...this.recipients,
      ];
    }
    for (const recipient of this.recipients) {
      stanzas.push(...(await recipient.wrapFileKey(fileKey)));
    }

    const hmacKey = hkdf(sha256, fileKey, undefined, "header", 32);
    const mac = hmac(sha256, hmacKey, encodeHeaderNoMAC(stanzas));
    const header = encodeHeader(stanzas, mac);

    const nonce = randomBytes(16);
    this.streamKey = hkdf(sha256, fileKey, nonce, "payload", 32);

    controller.enqueue(header);
    controller.enqueue(nonce);
  }

  incNonce() {
    for (let i = this.streamNonce.length - 2; i >= 0; i--) {
      this.streamNonce[i]++;
      if (this.streamNonce[i] !== 0) break;
    }
  }

  transform(chunk: Uint8Array, controller: TransformStreamDefaultController) {
    if (this.streamKey === null) {
      throw new Error("streamKey is not set, was `start` called?");
    }

    while (chunk.length > 0) {
      const bytesToBeWritten = Math.min(
        chunkSize - this.bufferSize,
        chunk.length
      );
      console.log("writing", bytesToBeWritten, "bytes")
      this.buffer.set(chunk.slice(0, bytesToBeWritten), this.bufferSize);
      this.bufferSize += bytesToBeWritten;
      chunk = chunk.subarray(bytesToBeWritten);

      // if the buffer is full and we still have more data, encrypt it
      // wait until we know we have one more byte at least, so we can always generate a valid end of stream chunk
      if (this.bufferSize === chunkSize && chunk.length > 0) {
        const chunk = chacha20poly1305(
          this.streamKey,
          this.streamNonce
        ).encrypt(this.buffer);
        console.log(chunk);
        controller.enqueue(chunk);
        this.buffer.fill(0);
        this.bufferSize = 0;
        this.incNonce();
      }
    }
  }
  flush(controller: TransformStreamDefaultController) {

    if (this.streamKey === null) {
      throw new Error("streamKey is not set, was `start` called?");
    }
    console.log("flushing", this.bufferSize, "bytes")

    this.streamNonce[11] = 1; // Last chunk flag.
    const chunk = chacha20poly1305(this.streamKey, this.streamNonce).encrypt(
      this.buffer.subarray(0, this.bufferSize)
    );
    controller.enqueue(chunk);
    this.buffer.fill(0);
    this.bufferSize = 0;
  }
}
