import type { ByteStringBuffer } from './ByteStringBuffer.ts';

/**
 * A hash algorithm instance that can compute message digests.
 *
 * @example
 * ```ts
 * import { sha256 } from 'rsa-oaep-encryption';
 *
 * const hash = sha256.create();
 * hash.update('Hello, World!');
 * const digest = hash.digest();
 * console.log(digest.toHex());
 * ```
 */
export interface HashAlgorithm {
    /** The algorithm name (e.g., 'sha256', 'sha512'). */
    algorithm: string;
    /** The block size in bytes used by the algorithm. */
    blockLength: number;
    /** The output digest size in bytes. */
    digestLength: number;
    /** The current message length in bytes being processed. */
    messageLength: number;
    /**
     * Resets the hash state to begin a new digest computation.
     * @returns This hash instance for method chaining.
     */
    start(): this;
    /**
     * Updates the hash with additional message data.
     * @param msg - The message string to add to the hash computation.
     * @returns This hash instance for method chaining.
     */
    update(msg: string): this;
    /**
     * Computes and returns the final message digest.
     * @returns A ByteStringBuffer containing the digest bytes.
     */
    digest(): ByteStringBuffer;
}

/**
 * A factory for creating hash algorithm instances.
 *
 * @example
 * ```ts
 * import { sha256, sha512 } from 'rsa-oaep-encryption';
 *
 * // sha256 and sha512 are HashAlgorithmCreator instances
 * const hash1 = sha256.create();
 * const hash2 = sha512.create();
 * ```
 */
export interface HashAlgorithmCreator {
    /**
     * Creates a new hash algorithm instance.
     * @returns A fresh HashAlgorithm instance ready for use.
     */
    create(): HashAlgorithm;
}
