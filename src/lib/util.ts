/**
 * Utility functions for web applications.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2018 Digital Bazaar, Inc.
 */

/**
 * Performs a per byte XOR between two byte strings and returns the result as a
 * string of bytes.
 *
 * @param s1 first string of bytes.
 * @param s2 second string of bytes.
 * @param n the number of bytes to XOR.
 *
 * @return the XOR'd result.
 */
export function xorBytes(s1: string, s2: string, n: number): string {
    let s3 = '';
    let b = 0;
    let t = '';
    let i = 0;
    let c = 0;
    for (; n > 0; --n, ++i) {
        b = s1.charCodeAt(i) ^ s2.charCodeAt(i);
        if (c >= 10) {
            s3 += t;
            t = '';
            c = 0;
        }
        t += String.fromCharCode(b);
        ++c;
    }
    s3 += t;
    return s3;
}

const Base64Idx = [
    /*43 -43 = 0*/
    /*'+',  1,  2,  3,'/' */
    62, -1, -1, -1, 63,

    /*'0','1','2','3','4','5','6','7','8','9' */
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61,

    /*15, 16, 17,'=', 19, 20, 21 */
    -1, -1, -1, 64, -1, -1, -1,

    /*65 - 43 = 22*/
    /*'A','B','C','D','E','F','G','H','I','J','K','L','M', */
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,

    /*'N','O','P','Q','R','S','T','U','V','W','X','Y','Z' */
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,

    /*91 - 43 = 48 */
    /*48, 49, 50, 51, 52, 53 */
    -1, -1, -1, -1, -1, -1,

    /*97 - 43 = 54*/
    /*'a','b','c','d','e','f','g','h','i','j','k','l','m' */
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,

    /*'n','o','p','q','r','s','t','u','v','w','x','y','z' */
    39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
];

/**
 * Base64 decodes a string into a 'binary' encoded string of bytes.
 *
 * @param input the base64-encoded input.
 *
 * @return the binary encoded string.
 */
export function decode64(input: string): string {
    // TODO: deprecate: "Deprecated. Use util.binary.base64.decode instead."

    // remove all non-base64 characters
    input = input.replace(/[^A-Za-z0-9+/=]/g, '');

    let output = '';
    let enc1: number;
    let enc2: number;
    let enc3: number;
    let enc4: number;
    let i = 0;

    while (i < input.length) {
        enc1 = Base64Idx[input.charCodeAt(i++) - 43];
        enc2 = Base64Idx[input.charCodeAt(i++) - 43];
        enc3 = Base64Idx[input.charCodeAt(i++) - 43];
        enc4 = Base64Idx[input.charCodeAt(i++) - 43];

        output += String.fromCharCode((enc1 << 2) | (enc2 >> 4));
        if (enc3 !== 64) {
            // decoded at least 2 bytes
            output += String.fromCharCode(((enc2 & 15) << 4) | (enc3 >> 2));
            if (enc4 !== 64) {
                // decoded 3 bytes
                output += String.fromCharCode(((enc3 & 3) << 6) | enc4);
            }
        }
    }

    return output;
}
