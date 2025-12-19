import type { HashAlgorithm } from './lib/defines.ts';
import { publicKeyFromPem } from './lib/rsa.ts';

export { ByteStringBuffer } from './lib/ByteStringBuffer.ts';
export type { HashAlgorithm, HashAlgorithmCreator } from './lib/defines.ts';
export { sha1 } from './lib/sha1.ts';
export { sha256 } from './lib/sha256.ts';
export { sha384, sha512 } from './lib/sha512.ts';

/**
 * RSA public key interface for encryption operations.
 *
 * @example
 * ```ts
 * const publicKey: RSAPublicKey = importPublicKey(pemString);
 * const encrypted = publicKey.encrypt('Hello', sha256.create());
 * ```
 */
export interface RSAPublicKey {
    /**
     * Encrypt data using RSA-OAEP algorithm.
     *
     * @param data - The string data to be encrypted.
     * @param hash - The hash algorithm instance to use (e.g., `sha256.create()`).
     * @returns The encrypted data as an ArrayBuffer.
     *
     * @example
     * ```ts
     * const encrypted = publicKey.encrypt('sensitive data', sha256.create());
     * ```
     */
    encrypt(data: string, hash: HashAlgorithm): ArrayBuffer;
}

/**
 * Import a RSA public key from a PEM format string.
 *
 * @param pem - The PEM format string containing the public key.
 * @returns An RSAPublicKey object that can be used to encrypt data.
 * @throws {Error} If the PEM format is invalid or the key cannot be parsed.
 *
 * @example
 * ```ts
 * import { importPublicKey, sha256 } from 'rsa-oaep-encryption';
 *
 * const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
 * MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
 * -----END PUBLIC KEY-----`;
 *
 * const publicKey = importPublicKey(PUBLIC_KEY);
 * const encrypted = publicKey.encrypt('Hello, World!', sha256.create());
 * ```
 */
export function importPublicKey(pem: string): RSAPublicKey {
    const publicKey = publicKeyFromPem(pem);

    return {
        encrypt(data: string, hash: HashAlgorithm): ArrayBuffer {
            return publicKey.encrypt(data, {
                md: hash,
            });
        },
    };
}