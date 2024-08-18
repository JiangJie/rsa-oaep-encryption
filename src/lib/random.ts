/**
 * An API for getting cryptographically-secure random bytes. The bytes are
 * generated using the Fortuna algorithm devised by Bruce Schneier and
 * Niels Ferguson.
 *
 * Getting strong random bytes is not yet easy to do in javascript. The only
 * truish random entropy that can be collected is from the mouse, keyboard, or
 * from timing with respect to page loads, etc. This generator makes a poor
 * attempt at providing random bytes when those sources haven't yet provided
 * enough entropy to initially seed or to reseed the PRNG.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2009-2014 Digital Bazaar, Inc.
 */

import { expandKey, updateBlock } from './aes.ts';
import { ByteStringBuffer } from './ByteStringBuffer.ts';
import { createPRNGContext, type PRNGPlugin } from './prng.ts';
import { sha256 } from './sha256.ts';

const _prng_aes_output = new Array<number>(4);
const _prng_aes_buffer = new ByteStringBuffer();

// the default prng plugin, uses AES-128
const prng_aes: PRNGPlugin = {
    formatKey(key: string): number[] {
        // convert the key into 32-bit integers
        const tmp = new ByteStringBuffer(key);
        const keyArray = [
            tmp.getInt32(),
            tmp.getInt32(),
            tmp.getInt32(),
            tmp.getInt32(),
        ];

        // return the expanded key
        return expandKey(keyArray);
    },
    formatSeed(seed: string): number[] {
        // convert seed into 32-bit integers
        const tmp = new ByteStringBuffer(seed);
        return [
            tmp.getInt32(),
            tmp.getInt32(),
            tmp.getInt32(),
            tmp.getInt32(),
        ];
    },
    cipher(key: number[], seed: number[]): string {
        updateBlock(key, seed, _prng_aes_output);
        _prng_aes_buffer.putInt32(_prng_aes_output[0]);
        _prng_aes_buffer.putInt32(_prng_aes_output[1]);
        _prng_aes_buffer.putInt32(_prng_aes_output[2]);
        _prng_aes_buffer.putInt32(_prng_aes_output[3]);
        return _prng_aes_buffer.getBytes();
    },
    increment(seed: number[]): number[] {
        // FIXME: do we care about carry or signed issues?
        ++seed[3];
        return seed;
    },
    md: sha256,
};

// create default prng context
/* Random API */
export const random = createPRNGContext(prng_aes);
