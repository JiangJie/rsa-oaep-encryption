import { assert } from '@std/assert';
import { sha1, sha256, sha384, sha512 } from '../src/mod.ts';

const data = 'rsa-oaep-encryption';

Deno.test('SHA encode', async () => {
    function compareBuffers(ab1: ArrayBuffer | Uint8Array, ab2: ArrayBuffer | Uint8Array): boolean {
        const view1 = new Uint8Array(ab1);
        const view2 = new Uint8Array(ab2);
        return view1.byteLength === view2.byteLength && view1.every((x, i) => x === view2[i]);
    }

    assert(compareBuffers(sha1.create().update(data).digest().toArrayBuffer(), await crypto.subtle.digest('SHA-1', new TextEncoder().encode(data))));
    assert(compareBuffers(sha256.create().update(data).digest().toArrayBuffer(), await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data))));
    assert(compareBuffers(sha384.create().update(data).digest().toArrayBuffer(), await crypto.subtle.digest('SHA-384', new TextEncoder().encode(data))));
    assert(compareBuffers(sha512.create().update(data).digest().toArrayBuffer(), await crypto.subtle.digest('SHA-512', new TextEncoder().encode(data))));
});