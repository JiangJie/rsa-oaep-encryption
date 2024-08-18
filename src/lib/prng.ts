/**
 * A javascript implementation of a cryptographically-secure
 * Pseudo Random Number Generator (PRNG). The Fortuna algorithm is followed
 * here though the use of SHA-256 is not enforced; when generating an
 * a PRNG context, the hashing algorithm and block cipher used for
 * the generator are specified via a plugin.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2014 Digital Bazaar, Inc.
 */

import { ByteStringBuffer } from './ByteStringBuffer.ts';
import type { HashAlgorithm } from './defines.ts';
import type { sha1 } from './sha1.ts';
import type { sha256 } from './sha256.ts';
import type { sha384, sha512 } from './sha512.ts';

export interface PRNGPlugin {
    formatKey(key: string): number[];
    formatSeed(seed: string): number[];
    cipher(key: number[], seed: number[]): string;
    increment(seed: number[]): number[];
    md: typeof sha1 | typeof sha256 | typeof sha384 | typeof sha512;
}

/**
 * Creates a new PRNG context.
 *
 * A PRNG plugin must be passed in that will provide:
 *
 * 1. A function that initializes the key and seed of a PRNG context. It
 *   will be given a 16 byte key and a 16 byte seed. Any key expansion
 *   or transformation of the seed from a byte string into an array of
 *   integers (or similar) should be performed.
 * 2. The cryptographic function used by the generator. It takes a key and
 *   a seed.
 * 3. A seed increment function. It takes the seed and returns seed + 1.
 * 4. An api to create a message digest.
 *
 * For an example, see random.js.
 *
 * @param plugin the PRNG plugin to use.
 */
export function createPRNGContext(plugin: PRNGPlugin) {
    // create 32 entropy pools (each is a message digest)
    const md = plugin.md;
    const pools = new Array<HashAlgorithm>(32);
    for (let i = 0; i < 32; ++i) {
        pools[i] = md.create();
    }

    const ctx = {
        plugin: plugin,
        key: [] as number[],
        seed: [] as number[],
        time: null,
        // number of reseeds so far
        reseeds: 0,
        // amount of data generated so far
        generated: 0,
        // no initial key bytes
        keyBytes: '',
        pools: pools,
        // entropy pools are written to cyclically, starting at index 0
        pool: 0,

        /**
         * Generates random bytes synchronously.
         *
         * @param count the number of random bytes to generate.
         *
         * @return count random bytes as a string.
         */
        generateSync(count: number): string {
            // simple generator using counter-based CBC
            const { cipher, increment, formatKey, formatSeed } = ctx.plugin;

            // paranoid deviation from Fortuna:
            // reset key for every request to protect previously
            // generated random bytes should the key be discovered;
            // there is no 100ms based reseeding because of this
            // forced reseed for every `generateSync` call
            ctx.key = [];

            const b = new ByteStringBuffer();
            while (b.length() < count) {
                if (ctx.key.length === 0) {
                    _reseedSync();
                }

                // generate the random bytes
                const bytes = cipher(ctx.key, ctx.seed);
                ctx.generated += bytes.length;
                b.putBytes(bytes);

                // generate bytes for a new key and seed
                ctx.key = formatKey(cipher(ctx.key, increment(ctx.seed)));
                ctx.seed = formatSeed(cipher(ctx.key, ctx.seed));
            }

            return b.getBytes(count);
        },

        /**
       * Adds entropy to a prng ctx's accumulator.
       *
       * @param bytes the bytes of entropy as a string.
       */
        collect(bytes: string) {
            // iterate over pools distributing entropy cyclically
            const count = bytes.length;
            for (let i = 0; i < count; ++i) {
                ctx.pools[ctx.pool].update(bytes.slice(i, i + 1));
                ctx.pool = (ctx.pool === 31) ? 0 : ctx.pool + 1;
            }
        },
    };

    /**
     * Private function that synchronously reseeds a generator.
     */
    function _reseedSync(): void {
        // not enough seed data...
        const needed = (32 - ctx.pools[0].messageLength) << 5;
        ctx.collect(defaultSeedFile(needed));
        _seed();
    }

    /**
     * Private function that seeds a generator once enough bytes are available.
     */
    function _seed(): void {
        // update reseed count
        ctx.reseeds = (ctx.reseeds === 0xffffffff) ? 0 : ctx.reseeds + 1;

        // goal is to update `key` via:
        // key = hash(key + s)
        //   where 's' is all collected entropy from selected pools, then...

        // create a plugin-based message digest
        const md = ctx.plugin.md.create();

        // consume current key bytes
        md.update(ctx.keyBytes);

        // digest the entropy of pools whose index k meet the
        // condition 'n mod 2^k == 0' where n is the number of reseeds
        let _2powK = 1;
        for (let k = 0; k < 32; ++k) {
            if (ctx.reseeds % _2powK === 0) {
                md.update(ctx.pools[k].digest().getBytes());
                ctx.pools[k].start();
            }
            _2powK = _2powK << 1;
        }

        // get digest for key bytes
        ctx.keyBytes = md.digest().getBytes();

        // paranoid deviation from Fortuna:
        // update `seed` via `seed = hash(key)`
        // instead of initializing to zero once and only
        // ever incrementing it
        md.start();
        md.update(ctx.keyBytes);
        const seedBytes = md.digest().getBytes();

        // update state
        ctx.key = ctx.plugin.formatKey(ctx.keyBytes);
        ctx.seed = ctx.plugin.formatSeed(seedBytes);
        ctx.generated = 0;
    }

    return ctx;
}

/**
     * The built-in default seedFile. This seedFile is used when entropy
     * is needed immediately.
     *
     * @param needed the number of bytes that are needed.
     *
     * @return the random bytes.
     */
function defaultSeedFile(needed: number): string {
    const b = new ByteStringBuffer();

    // be sad and add some weak random data
    if (b.length() < needed) {
        /* Draws from Park-Miller "minimal standard" 31 bit PRNG,
        implemented with David G. Carta's optimization: with 32 bit math
        and without division (Public Domain). */
        let hi: number;
        let lo: number;
        let next: number;
        let seed = Math.floor(Math.random() * 0x010000);
        while (b.length() < needed) {
            lo = 16807 * (seed & 0xFFFF);
            hi = 16807 * (seed >> 16);
            lo += (hi & 0x7FFF) << 16;
            lo += hi >> 15;
            lo = (lo & 0x7FFFFFFF) + (lo >> 31);
            seed = lo & 0xFFFFFFFF;

            // consume lower 3 bytes of seed
            for (let i = 0; i < 3; ++i) {
                // throw in more pseudo random
                next = seed >>> (i << 3);
                next ^= Math.floor(Math.random() * 0x0100);
                b.putByte(next & 0xFF);
            }
        }
    }

    return b.getBytes(needed);
}
