/**
 * Constructor for a binary string backed byte buffer.
 *
 * @param [b] the bytes to wrap (either encoded as string, one byte per
 *          character, or as an ArrayBuffer or Typed Array).
 */
export class ByteStringBuffer {
    // used for v8 optimization
    private _constructedStringLength = 0;
    private data = '';

    read = 0;

    constructor(b?: string) {
        if (typeof b === 'string') {
            this.data = b;
        }
    }

    /* Note: This is an optimization for V8-based browsers. When V8 concatenates
      a string, the strings are only joined logically using a "cons string" or
      "constructed/concatenated string". These containers keep references to one
      another and can result in very large memory usage. For example, if a 2MB
      string is constructed by concatenating 4 bytes together at a time, the
      memory usage will be ~44MB; so ~22x increase. The strings are only joined
      together when an operation requiring their joining takes place, such as
      substr(). This function is called when adding data to this buffer to ensure
      these types of strings are periodically joined to reduce the memory
      footprint. */
    private _optimizeConstructedString(x: number): void {
        this._constructedStringLength += x;
    }

    /**
     * Gets the number of bytes in this buffer.
     *
     * @return the number of bytes in this buffer.
     */
    length(): number {
        return this.data.length - this.read;
    }

    /**
     * Puts a byte in this buffer.
     *
     * @param b the byte to put.
     *
     * @return this buffer.
     */
    putByte(b: number): this {
        return this.putBytes(String.fromCharCode(b));
    }

    /**
     * Puts bytes in this buffer.
     *
     * @param bytes the bytes (as a binary encoded string) to put.
     *
     * @return this buffer.
     */
    putBytes(bytes: string): this {
        this.data += bytes;
        this._optimizeConstructedString(bytes.length);
        return this;
    }

    /**
     * Puts a 32-bit integer in this buffer in big-endian order.
     *
     * @param i the 32-bit integer.
     *
     * @return this buffer.
     */
    putInt32(i: number): this {
        return this.putBytes(
            String.fromCharCode(i >> 24 & 0xFF) +
            String.fromCharCode(i >> 16 & 0xFF) +
            String.fromCharCode(i >> 8 & 0xFF) +
            String.fromCharCode(i & 0xFF));
    }

    /**
     * Gets a byte from this buffer and advances the read pointer by 1.
     *
     * @return the byte.
     */
    getByte(): number {
        return this.data.charCodeAt(this.read++);
    }

    /**
     * Gets a uint32 from this buffer in big-endian order and advances the read
     * pointer by 4.
     *
     * @return the word.
     */
    getInt32(): number {
        const rval = (
            this.data.charCodeAt(this.read) << 24 ^
            this.data.charCodeAt(this.read + 1) << 16 ^
            this.data.charCodeAt(this.read + 2) << 8 ^
            this.data.charCodeAt(this.read + 3));
        this.read += 4;
        return rval;
    }

    /**
     * Gets an n-bit integer from this buffer in big-endian order and advances the
     * read pointer by ceil(n/8).
     *
     * @param n the number of bits in the integer (8, 16, 24, or 32).
     *
     * @return the integer.
     */
    getInt(n: 8 | 16 | 24 | 32): number {
        let rval = 0;
        do {
            // TODO: Use (rval * 0x100) if adding support for 33 to 53 bits.
            rval = (rval << 8) + this.data.charCodeAt(this.read++);
            n -= 8;
        } while (n > 0);
        return rval;
    }

    /**
     * Reads bytes out as a binary encoded string and clears them from the
     * buffer. Note that the resulting string is binary encoded (in node.js this
     * encoding is referred to as `binary`, it is *not* `utf8`).
     *
     * @param count the number of bytes to read, undefined or null for all.
     *
     * @return a binary encoded string of bytes.
     */
    getBytes(count?: number): string {
        let rval: string;
        if (count) {
            // read count bytes
            count = Math.min(this.length(), count);
            rval = this.data.slice(this.read, this.read + count);
            this.read += count;
        } else if (count === 0) {
            rval = '';
        } else {
            // read all bytes, optimize to only copy when needed
            rval = this.data;
            this.clear();
        }
        return rval;
    }

    /**
     * Gets a binary encoded string of the bytes from this buffer without
     * modifying the read pointer.
     *
     * @param count the number of bytes to get, omit to get all.
     *
     * @return a string full of binary encoded characters.
     */
    bytes(count?: number): string {
        return typeof count === 'number'
            ? this.data.slice(this.read, this.read + count)
            : this.data.slice(this.read);
    }

    /**
     * Compacts this buffer.
     *
     * @return this buffer.
     */
    compact(): this {
        if (this.read > 0) {
            this.data = this.data.slice(this.read);
            this.read = 0;
        }
        return this;
    }

    /**
     * Clears this buffer.
     *
     * @return this buffer.
     */
    clear(): this {
        this.data = '';
        this.read = 0;
        return this;
    }

    /**
     * Converts this buffer to a hexadecimal string.
     *
     * @return a hexadecimal string.
     */
    toHex(): string {
        let rval = '';
        for (let i = this.read; i < this.data.length; ++i) {
            const b = this.data.charCodeAt(i);
            if (b < 16) {
                rval += '0';
            }
            rval += b.toString(16);
        }
        return rval;
    }

    /**
     * Converts this buffer to an ArrayBuffer.
     *
     * @return An ArrayBuffer.
     */
    toArrayBuffer(): ArrayBuffer {
        const ab = new ArrayBuffer(this.length());
        const u8a = new Uint8Array(ab);

        for (let i = this.read; i < this.data.length; ++i) {
            u8a[i] = this.data.charCodeAt(i);
        }

        return ab;
    }
}