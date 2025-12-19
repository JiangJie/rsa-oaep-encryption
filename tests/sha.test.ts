import { describe, expect, it } from 'vitest';
import { sha1, sha256, sha384, sha512 } from '../src/mod.ts';

const data = 'rsa-oaep-encryption';

function compareBuffers(ab1: ArrayBuffer | Uint8Array, ab2: ArrayBuffer | Uint8Array): boolean {
    const view1 = new Uint8Array(ab1);
    const view2 = new Uint8Array(ab2);
    return view1.byteLength === view2.byteLength && view1.every((x, i) => x === view2[i]);
}

describe('SHA encode', () => {
    it('should produce correct SHA-1 hash', async () => {
        const result = sha1.create().update(data).digest().toArrayBuffer();
        const expected = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(data));
        expect(compareBuffers(result, expected)).toBe(true);
    });

    it('should produce correct SHA-256 hash', async () => {
        const result = sha256.create().update(data).digest().toArrayBuffer();
        const expected = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
        expect(compareBuffers(result, expected)).toBe(true);
    });

    it('should produce correct SHA-384 hash', async () => {
        const result = sha384.create().update(data).digest().toArrayBuffer();
        const expected = await crypto.subtle.digest('SHA-384', new TextEncoder().encode(data));
        expect(compareBuffers(result, expected)).toBe(true);
    });

    it('should produce correct SHA-512 hash', async () => {
        const result = sha512.create().update(data).digest().toArrayBuffer();
        const expected = await crypto.subtle.digest('SHA-512', new TextEncoder().encode(data));
        expect(compareBuffers(result, expected)).toBe(true);
    });
});
