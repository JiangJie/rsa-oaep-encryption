import { BigInteger as JsbnBigInteger } from './jsbn.ts';

/**
 * Unified big-integer interface abstracting native BigInt and jsbn BigInteger.
 * Only the methods required by the RSA pipeline are exposed.
 */
export interface IBigInteger {
    /** Returns the number of bits in this integer. */
    bitLength(): number;
    /** Modular exponentiation: this^e mod m */
    modPow(e: IBigInteger, m: IBigInteger): IBigInteger;
    /** Returns the hex string representation (no 0x prefix, no leading zeros). */
    toString(): string;
}

// ---- Native BigInt implementation ----

class NativeBigInteger implements IBigInteger {
    constructor(
        private readonly value: bigint,
    ) {
    }

    bitLength(): number {
        if (this.value === BigInt(0)) return 0;
        return this.value.toString(2).length;
    }

    modPow(e: IBigInteger, m: IBigInteger): IBigInteger {
        const exp = (e as NativeBigInteger).value;
        const mod = (m as NativeBigInteger).value;
        return new NativeBigInteger(modPowBigInt(this.value, exp, mod));
    }

    toString(): string {
        if (this.value === BigInt(0)) return '';
        return this.value.toString(16);
    }
}

/** Binary square-and-multiply modular exponentiation. */
function modPowBigInt(base: bigint, exp: bigint, mod: bigint): bigint {
    if (mod === BigInt(1)) return BigInt(0);
    let result = BigInt(1);
    base = base % mod;
    while (exp > BigInt(0)) {
        if (exp & BigInt(1)) {
            result = (result * base) % mod;
        }
        exp >>= BigInt(1);
        base = (base * base) % mod;
    }
    return result;
}

// ---- Runtime detection ----

const useNativeBigInt = typeof BigInt === 'function';

/**
 * Create an IBigInteger from a hex string.
 * Uses native BigInt when available, falls back to jsbn BigInteger otherwise.
 *
 * @param hex - Hexadecimal string (no 0x prefix).
 * @returns An IBigInteger instance.
 *
 * @example
 * ```ts
 * const n = createBigInteger('deadbeef');
 * n.bitLength(); // 32
 * n.toString();  // 'deadbeef'
 * ```
 */
export function createBigInteger(hex: string): IBigInteger {
    if (useNativeBigInt) {
        const value = hex.length > 0 ? BigInt(`0x${hex}`) : BigInt(0);
        return new NativeBigInteger(value);
    }
    return new JsbnBigInteger(hex) as unknown as IBigInteger;
}
