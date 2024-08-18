/**
 * Partial implementation of PKCS#1 v2.2: RSA-OEAP
 *
 * Modified but based on the following MIT and BSD licensed code:
 *
 * https://github.com/kjur/jsjws/blob/master/rsa.js:
 *
 * The 'jsjws'(JSON Web Signature JavaScript Library) License
 *
 * Copyright (c) 2012 Kenji Urushima
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * http://webrsa.cvs.sourceforge.net/viewvc/webrsa/Client/RSAES-OAEP.js?content-type=text%2Fplain:
 *
 * RSAES-OAEP.js
 * $Id: RSAES-OAEP.js,v 1.1.1.1 2003/03/19 15:37:20 ellispritchard Exp $
 * JavaScript Implementation of PKCS #1 v2.1 RSA CRYPTOGRAPHY STANDARD (RSA Laboratories, June 14, 2002)
 * Copyright (C) Ellis Pritchard, Guardian Unlimited 2003.
 * Contact: ellis@nukinetics.com
 * Distributed under the BSD License.
 *
 * Official documentation: http://www.rsa.com/rsalabs/node.asp?id=2125
 *
 * @author Evan Jones (http://evanjones.ca/)
 * @author Dave Longley
 *
 * Copyright (c) 2013-2014 Digital Bazaar, Inc.
 */

import type { HashAlgorithm } from './defines.ts';
import type { BigInteger } from './jsbn.ts';
import { random } from './random.ts';
import { xorBytes } from './util.ts';

export interface RSAEncodeOptions {
    md: HashAlgorithm;
}

/**
 * Encode the given RSAES-OAEP message (M) using key, with optional label (L)
 * and seed.
 *
 * This method does not perform RSA encryption, it only encodes the message
 * using RSAES-OAEP.
 *
 * @param key the RSA key to use.
 * @param message the message to encode.
 * @param options the options to use:
 *          label an optional label to use.
 *          seed the seed to use.
 *          md the message digest object to use, undefined for SHA-1.
 *          mgf1 optional mgf1 parameters:
 *            md the message digest object to use for MGF1.
 *
 * @return the encoded message bytes.
 */
export function encode_rsa_oaep(key: BigInteger, message: string, options: RSAEncodeOptions): string {
    // parse arguments
    const md = options.md;

    // default OAEP to SHA-1 message digest
    md.start();

    // default MGF-1 to same as OAEP
    const mgf1Md = md;

    // compute length in bytes and check output
    const keyLength = Math.ceil(key.bitLength() / 8);
    const maxLength = keyLength - 2 * md.digestLength - 2;

    const label = '';
    md.update(label);
    const lHash = md.digest();

    let PS = '';
    const PS_length = maxLength - message.length;
    for (let i = 0; i < PS_length; i++) {
        PS += '\x00';
    }

    const DB = lHash.getBytes() + PS + '\x01' + message;

    const seed = random.generateSync(md.digestLength);

    const dbMask = rsa_mgf1(seed, keyLength - md.digestLength - 1, mgf1Md);
    const maskedDB = xorBytes(DB, dbMask, DB.length);

    const seedMask = rsa_mgf1(maskedDB, md.digestLength, mgf1Md);
    const maskedSeed = xorBytes(seed, seedMask, seed.length);

    // return encoded message
    return '\x00' + maskedSeed + maskedDB;
}

function rsa_mgf1(seed: string, maskLength: number, hash: HashAlgorithm): string {
    let t = '';
    const count = Math.ceil(maskLength / hash.digestLength);
    for (let i = 0; i < count; ++i) {
        const c = String.fromCharCode(
            (i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF);
        hash.start();
        hash.update(seed + c);
        t += hash.digest().getBytes();
    }
    return t.substring(0, maskLength);
}
