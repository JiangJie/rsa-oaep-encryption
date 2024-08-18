// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

/*
Licensing (LICENSE)
-------------------

This software is covered under the following copyright:
*/
/*
 * Copyright (c) 2003-2005  Tom Wu
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */
/*
Address all questions regarding this license to:

  Tom Wu
  tjw@cs.Stanford.EDU
*/

// Bits per digit
const dbits = 28;

const BI_FP = 52;

// (public) Constructor
export class BigInteger {
    private s = 0;
    t = 0;
    data: number[] = [];
    DB = dbits;
    DM = (1 << dbits) - 1;
    private DV = 1 << dbits;
    private FV = Math.pow(2, BI_FP);
    private F1 = BI_FP - dbits;
    private F2 = 2 * dbits - BI_FP;

    constructor(a?: string) {
        if (a != null) {
            this.fromString(a);
        }
    }

    am(i: number, x: number, w: BigInteger, j: number, c: number, n: number): number {
        const xl = x & 0x3fff,
            xh = x >> 14;
        while (--n >= 0) {
            let l = this.data[i] & 0x3fff;
            const h = this.data[i++] >> 14;
            const m = xh * l + h * xl;
            l = xl * l + ((m & 0x3fff) << 14) + w.data[j] + c;
            c = (l >> 28) + (m >> 14) + xh * h;
            w.data[j++] = l & 0xfffffff;
        }
        return c;
    }

    // (public) return the number of bits in "this"
    bitLength(): number {
        return (
            this.DB * (this.t - 1) + nbits(this.data[this.t - 1] ^ (this.s & this.DM))
        );
    }

    // (protected) r = this << n*DB
    dlShiftTo(n: number, r: BigInteger): void {
        let i = this.t - 1;
        for (; i >= 0; --i) r.data[i + n] = this.data[i];
        for (i = n - 1; i >= 0; --i) r.data[i] = 0;
        r.t = this.t + n;
        r.s = this.s;
    }

    // (protected) r = this >> n*DB
    drShiftTo(n: number, r: BigInteger): void {
        for (let i = n; i < this.t; ++i) r.data[i - n] = this.data[i];
        r.t = Math.max(this.t - n, 0);
        r.s = this.s;
    }

    // (protected) r = this << n
    lShiftTo(n: number, r: BigInteger): void {
        const bs = n % this.DB;
        const cbs = this.DB - bs;
        const bm = (1 << cbs) - 1;
        const ds = Math.floor(n / this.DB);
        let c = (this.s << bs) & this.DM;
        let i = this.t - 1;
        for (; i >= 0; --i) {
            r.data[i + ds + 1] = (this.data[i] >> cbs) | c;
            c = (this.data[i] & bm) << bs;
        }
        r.data[ds] = c;
        r.t = this.t + ds + 1;
        r.s = this.s;
        r.clamp();
    }

    // (protected) r = this >> n
    rShiftTo(n: number, r: BigInteger): void {
        r.s = this.s;
        const ds = Math.floor(n / this.DB);
        const bs = n % this.DB;
        const cbs = this.DB - bs;
        const bm = (1 << bs) - 1;
        r.data[0] = this.data[ds] >> bs;
        for (let i = ds + 1; i < this.t; ++i) {
            r.data[i - ds - 1] |= (this.data[i] & bm) << cbs;
            r.data[i - ds] = this.data[i] >> bs;
        }
        if (bs > 0) r.data[this.t - ds - 1] |= (this.s & bm) << cbs;
        r.t = this.t - ds;
        r.clamp();
    }

    // (protected) r = this - a
    subTo(a: BigInteger, r: BigInteger): void {
        let i = 0;
        let c = 0;
        const m = Math.min(a.t, this.t);
        while (i < m) {
            c += this.data[i] - a.data[i];
            r.data[i++] = c & this.DM;
            c >>= this.DB;
        }
        c -= a.s;
        while (i < this.t) {
            c += this.data[i];
            r.data[i++] = c & this.DM;
            c >>= this.DB;
        }
        r.t = i;
        r.clamp();
    }

    // (protected) r = this * a, r != this,a (HAC 14.12)
    // "this" should be the larger one if appropriate.
    multiplyTo(a: BigInteger, r: BigInteger): void {
        const x = this.abs(),
            y = a.abs();
        let i = x.t;
        r.t = i + y.t;
        while (--i >= 0) r.data[i] = 0;
        for (i = 0; i < y.t; ++i) r.data[i + x.t] = x.am(0, y.data[i], r, i, 0, x.t);
        r.s = 0;
        r.clamp();
    }

    // (protected) r = this^2, r != this (HAC 14.16)
    squareTo(r: BigInteger): void {
        const x = this.abs();
        let i = (r.t = 2 * x.t);
        while (--i >= 0) r.data[i] = 0;
        for (i = 0; i < x.t - 1; ++i) {
            const c = x.am(i, x.data[i], r, 2 * i, 0, 1);
            if (
                (r.data[i + x.t] += x.am(
                    i + 1,
                    2 * x.data[i],
                    r,
                    2 * i + 1,
                    c,
                    x.t - i - 1
                )) >= x.DV
            ) {
                r.data[i + x.t] -= x.DV;
                r.data[i + x.t + 1] = 1;
            }
        }
        if (r.t > 0) r.data[r.t - 1] += x.am(i, x.data[i], r, 2 * i, 0, 1);
        r.s = 0;
        r.clamp();
    }

    // (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
    // r != q, this != m.  q or r may be null.
    divRemTo(m: BigInteger, r: BigInteger): void {
        const pm = m.abs();
        const pt = this.abs();
        const y = nbi()
        const nsh = this.DB - nbits(pm.data[pm.t - 1]); // normalize modulus
        pm.lShiftTo(nsh, y);
        pt.lShiftTo(nsh, r);
        const ys = y.t;
        const y0 = y.data[ys - 1];
        const yt = y0 * (1 << this.F1) + (y.data[ys - 2] >> this.F2);
        const d1 = this.FV / yt,
            d2 = (1 << this.F1) / yt,
            e = 1 << this.F2;
        let i = r.t;
        let j = i - ys;
        const t = nbi();
        y.dlShiftTo(j, t);
        BigIntegerONE.dlShiftTo(ys, t);
        t.subTo(y, y); // "negative" y so we can replace sub with am later
        while (--j >= 0) {
            // Estimate quotient digit
            --i;
            const qd = Math.floor(r.data[i] * d1 + (r.data[i - 1] + e) * d2);
            r.data[i] += y.am(0, qd, r, j, 0, ys);
        }
        r.t = ys;
        r.clamp();
        if (nsh > 0) r.rShiftTo(nsh, r); // Denormalize remainder
    }

    // (protected) return "-1/this % 2^DB"; useful for Mont. reduction
    // justification:
    //         xy == 1 (mod m)
    //         xy =  1+km
    //   xy(2-xy) = (1+km)(1-km)
    // x[y(2-xy)] = 1-k^2m^2
    // x[y(2-xy)] == 1 (mod m^2)
    // if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
    // should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
    // JS multiply "overflows" differently from C/C++, so care is needed here.
    invDigit(): number {
        const x = this.data[0];
        let y = x & 3; // y == 1/x mod 2^2
        y = (y * (2 - (x & 0xf) * y)) & 0xf; // y == 1/x mod 2^4
        y = (y * (2 - (x & 0xff) * y)) & 0xff; // y == 1/x mod 2^8
        y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff; // y == 1/x mod 2^16
        // last step - calculate inverse mod DV directly;
        // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
        y = (y * (2 - ((x * y) % this.DV))) % this.DV; // y == 1/x mod 2^dbits
        // we really want the negative inverse, and -DV < y < DV
        return -y;
    }

    // (protected) copy this to r
    copyTo(r: BigInteger): void {
        for (let i = this.t - 1; i >= 0; --i) r.data[i] = this.data[i];
        r.t = this.t;
        r.s = this.s;
    }

    // (protected) set from integer value x, -DV <= x < DV
    fromInt(x: number): void {
        this.t = 1;
        this.s = 0;
        this.data[0] = x;
    }

    // (protected) set from string and radix
    fromString(s: string): void {
        const k = 4;
        this.t = 0;
        this.s = 0;
        let i = s.length;
        let sh = 0;
        while (--i >= 0) {
            const x = intAt(s, i);
            if (sh === 0) this.data[this.t++] = x;
            else this.data[this.t - 1] |= x << sh;
            sh += k;
            if (sh >= this.DB) sh -= this.DB;
        }
        this.clamp();
    }

    // (protected) clamp off excess high words
    clamp(): void {
        const c = this.s & this.DM;
        while (this.t > 0 && this.data[this.t - 1] === c) --this.t;
    }

    // (public) return string representation in given radix
    toString(): string {
        const k = 4;
        const km = (1 << k) - 1;
        let d,
            m = false,
            r = '',
            i = this.t;
        let p = this.DB - ((i * this.DB) % k);
        if (i-- > 0) {
            while (i >= 0) {
                d = (this.data[i] >> (p -= k)) & km;
                if (p <= 0) {
                    p += this.DB;
                    --i;
                }
                if (d > 0) m = true;
                if (m) r += int2char(d);
            }
        }
        return r;
    }

    // (public) |this|
    abs(): this {
        return this;
    }

    //(public) this^e % m (HAC 14.85)
    modPow(e: BigInteger, m: BigInteger): BigInteger {
        let i = e.bitLength();
        let r = nbv(1);
        const k = 1;
        const z = new Montgomery(m);

        // precomputation
        const g = [];
        let n = 3;
        const k1 = k - 1,
            km = (1 << k) - 1;
        g[1] = z.convert(this);

        let j = e.t - 1,
            w,
            is1 = true,
            r2 = nbi(),
            t;
        i = nbits(e.data[j]) - 1;
        while (j >= 0) {
            w = (e.data[j] >> (i - k1)) & km;

            n = k;
            if ((i -= n) < 0) {
                i += this.DB;
                --j;
            }
            if (is1) {
                // ret == 1, don't bother squaring or multiplying it
                g[w].copyTo(r);
                is1 = false;
            } else {
                z.sqrTo(r, r2);
                z.mulTo(r2, g[w], r);
            }

            while (j >= 0 && (e.data[j] & (1 << i)) === 0) {
                z.sqrTo(r, r2);
                t = r;
                r = r2;
                r2 = t;
                i--;
            }
        }
        return z.revert(r);
    }
}

//BigInteger interfaces not implemented in jsbn:

//BigInteger(int signum, byte[] magnitude)
//double doubleValue()
//float floatValue()
//int hashCode()
//long longValue()
//static BigInteger valueOf(long val)

// "constants"
const BigIntegerONE = nbv(1);

// return new, unset BigInteger
function nbi(): BigInteger {
    return new BigInteger();
}

// return bigint initialized to value
function nbv(i: number): BigInteger {
    const r = nbi();
    r.fromInt(i);
    return r;
}

// Digit conversions
const BI_RM = '0123456789abcdefghijklmnopqrstuvwxyz';
const BI_RC: number[] = [];
let vv: number;
let rr = '0'.charCodeAt(0);
for (vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = 'a'.charCodeAt(0);
for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n: number): string {
    return BI_RM.charAt(n);
}
function intAt(s: string, i: number): number {
    const c = BI_RC[s.charCodeAt(i)];
    return c;
}

// returns bit length of the integer x
function nbits(x: number): number {
    let r = 1,
        t;
    if ((t = x >>> 16) != 0) {
        x = t;
        r += 16;
    }
    if ((t = x >> 2) != 0) {
        x = t;
        r += 2;
    }
    if ((t = x >> 1) != 0) {
        x = t;
        r += 1;
    }
    return r;
}

// Montgomery reduction
class Montgomery {
    private m: BigInteger;
    private mp: number;
    private mpl: number;
    private mph: number;
    private um: number;
    private mt2: number;

    constructor(m: BigInteger) {
        this.m = m;
        this.mp = m.invDigit();
        this.mpl = this.mp & 0x7fff;
        this.mph = this.mp >> 15;
        this.um = (1 << (m.DB - 15)) - 1;
        this.mt2 = 2 * m.t;
    }

    // xR mod m
    convert(x: BigInteger): BigInteger {
        const r = nbi();
        x.abs().dlShiftTo(this.m.t, r);
        r.divRemTo(this.m, r);
        return r;
    }

    // x/R mod m
    revert(x: BigInteger): BigInteger {
        const r = nbi();
        x.copyTo(r);
        this.reduce(r);
        return r;
    }

    // x = x/R mod m (HAC 14.32)
    reduce(x: BigInteger): void {
        while (x.t <= this.mt2)
            // pad x so am has enough room later
            x.data[x.t++] = 0;
        for (let i = 0; i < this.m.t; ++i) {
            // faster way of calculating u0 = x.data[i]*mp mod DV
            let j = x.data[i] & 0x7fff;
            const u0 =
                (j * this.mpl +
                    (((j * this.mph + (x.data[i] >> 15) * this.mpl) & this.um) << 15)) &
                x.DM;
            // use am to combine the multiply-shift-add into one call
            j = i + this.m.t;
            x.data[j] += this.m.am(0, u0, x, i, 0, this.m.t);
            // propagate carry
        }
        x.clamp();
        x.drShiftTo(this.m.t, x);
    }

    // r = "x^2/R mod m"; x != r
    sqrTo(x: BigInteger, r: BigInteger): void {
        x.squareTo(r);
        this.reduce(r);
    }

    // r = "xy/R mod m"; x,y != r
    mulTo(x: BigInteger, y: BigInteger, r: BigInteger): void {
        x.multiplyTo(y, r);
        this.reduce(r);
    }
}
