import type { HashAlgorithm } from './lib/defines.ts';
import { privateKeyFromPem, publicKeyFromPem } from './lib/rsa.ts';

export { ByteStringBuffer } from './lib/ByteStringBuffer.ts';
export type { HashAlgorithm, HashAlgorithmCreator } from './lib/defines.ts';
export { sha1 } from './lib/sha1.ts';
export { sha256 } from './lib/sha256.ts';
export { sha384, sha512 } from './lib/sha512.ts';

/**
 * RSA public key.
 */
export interface RSAPublicKey {
    /**
     * Encrypt data using RSA key.
     * @param data A string to be encrypted.
     * @param hash Which hash algorithm to use.
     * @returns Encrypted data as ArrayBuffer.
     */
    encrypt(data: string, hash: HashAlgorithm): ArrayBuffer;
}

/**
 * Import a RSA public key from a PEM format string.
 * Used to encrypt data.
 *
 * @param pem The PEM format string.
 * @returns A function that can be used to encrypt data.
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

/**
 * RSA private key.
 */
export interface RSAPrivateKey {
    /**
     * Decrypt data using RSA key.
     * @param data A string to be decrypted.
     * @param hash Which hash algorithm to use.
     * @returns Decrypted data as string.
     */
    decrypt(data: string, hash: HashAlgorithm): string;
}

/**
 * Import a RSA private key from a PEM format string.
 * Used to decrypt data.
 *
 * @param pem The PEM format string.
 * @returns A function that can be used to decrypt data.
 */
export function importPrivateKey(pem: string): RSAPrivateKey {
    const privateKey = privateKeyFromPem(pem);

    return {
        decrypt(data: string, hash: HashAlgorithm): string {
            return privateKey.decrypt(data, {
                md: hash,
            });
        },
    };
}
