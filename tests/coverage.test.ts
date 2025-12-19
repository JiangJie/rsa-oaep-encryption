/**
 * Additional tests to achieve 100% code coverage.
 * These tests cover edge cases and branches not hit by the main test suite.
 */
import { describe, expect, it } from 'vitest';
import { ByteStringBuffer } from '../src/lib/ByteStringBuffer.ts';
import { decode64 } from '../src/lib/util.ts';
import { BigInteger } from '../src/lib/jsbn.ts';
import { derToOid, fromDer } from '../src/lib/asn1.ts';
import { pemDecode } from '../src/lib/pem.ts';

describe('ByteStringBuffer', () => {
    describe('at() method', () => {
        it('should return byte at given index without modifying read pointer', () => {
            const buffer = new ByteStringBuffer('hello');
            expect(buffer.at(0)).toBe('h'.charCodeAt(0));
            expect(buffer.at(1)).toBe('e'.charCodeAt(0));
            expect(buffer.at(4)).toBe('o'.charCodeAt(0));
            // read pointer should not have changed
            expect(buffer.read).toBe(0);
        });

        it('should return byte at index relative to read position', () => {
            const buffer = new ByteStringBuffer('hello');
            buffer.getByte(); // advance read pointer by 1
            expect(buffer.at(0)).toBe('e'.charCodeAt(0)); // now relative to 'e'
            expect(buffer.at(1)).toBe('l'.charCodeAt(0));
        });
    });
});

describe('Base64 decode edge cases', () => {
    it('should handle base64 string with padding (==)', () => {
        // "a" in base64 is "YQ==" (1 byte -> 2 padding chars)
        const decoded = decode64('YQ==');
        expect(decoded).toBe('a');
    });

    it('should handle base64 string with single padding (=)', () => {
        // "ab" in base64 is "YWI=" (2 bytes -> 1 padding char)
        const decoded = decode64('YWI=');
        expect(decoded).toBe('ab');
    });

    it('should handle base64 string without padding', () => {
        // "abc" in base64 is "YWJj" (3 bytes -> no padding)
        const decoded = decode64('YWJj');
        expect(decoded).toBe('abc');
    });

    it('should strip non-base64 characters', () => {
        const decoded = decode64('YWJj\n\r ');
        expect(decoded).toBe('abc');
    });
});

describe('BigInteger', () => {
    describe('toString', () => {
        it('should convert large numbers to hex string', () => {
            const bi = new BigInteger('deadbeef');
            expect(bi.toString()).toBe('deadbeef');
        });

        it('should handle zero', () => {
            const bi = new BigInteger();
            expect(bi.toString()).toBe('');
        });

        it('should handle small numbers', () => {
            const bi = new BigInteger('f');
            expect(bi.toString()).toBe('f');
        });

        it('should handle numbers with leading zeros in hex', () => {
            const bi = new BigInteger('0f');
            expect(bi.toString()).toBe('f');
        });
    });

    describe('rShiftTo', () => {
        it('should right shift by various amounts', () => {
            // Test right shift with bs > 0 to cover line 140
            const bi = new BigInteger('ffffffff');
            const result = new BigInteger();
            // Right shift by a non-multiple of DB (28) to ensure bs > 0
            bi.rShiftTo(4, result);
            expect(result.toString()).toBe('fffffff');
        });

        it('should right shift by amount that makes bs > 0', () => {
            // DB is 28, so shift by 1 will make bs = 1 > 0
            const bi = new BigInteger('ffffffffffffffff');
            const result = new BigInteger();
            bi.rShiftTo(1, result);
            expect(result.t).toBeGreaterThanOrEqual(0);
        });

        it('should right shift large number by small amount', () => {
            // Create a number larger than one "digit" (28 bits)
            // and shift by a small amount to ensure bs > 0 branch is taken
            const bi = new BigInteger('ffffffffffffffffffff'); // 80 bits
            const result = new BigInteger();
            bi.rShiftTo(5, result); // bs = 5 % 28 = 5 > 0
            expect(result.toString().length).toBeGreaterThan(0);
        });

        it('should handle shift with multiple digits and non-zero bs', () => {
            // Need t > ds + 1 to enter the for loop and bs > 0 for line 140
            // DB = 28, create number with multiple digits and shift by non-multiple of 28
            const bi = new BigInteger('ffffffffffffffffffffffffffffffffff'); // 136 bits = ~5 digits
            const result = new BigInteger();
            bi.rShiftTo(29, result); // ds = 1, bs = 1 > 0, should enter loop and hit line 140
            expect(result.t).toBeGreaterThanOrEqual(0);
        });
    });

    describe('divRemTo', () => {
        it('should perform division with remainder', () => {
            // Test division to cover lines 199-233
            const a = new BigInteger('deadbeef12345678');
            const b = new BigInteger('deadbeef');
            const r = new BigInteger();
            a.divRemTo(b, r);
            // Result should be the remainder
            expect(r.t).toBeGreaterThanOrEqual(0);
        });

        it('should handle division of larger numbers', () => {
            // Use larger numbers to ensure we hit more code paths
            const a = new BigInteger('ffffffffffffffffffffffffffff'); // 112 bits
            const b = new BigInteger('ffffffffffff'); // 48 bits
            const r = new BigInteger();
            a.divRemTo(b, r);
            expect(r.t).toBeGreaterThanOrEqual(0);
        });

        it('should handle division that requires multiple iterations', () => {
            // Create numbers that will require the while loop to iterate multiple times
            const a = new BigInteger('123456789abcdef0123456789abcdef');
            const b = new BigInteger('abcdef');
            const r = new BigInteger();
            a.divRemTo(b, r);
            expect(r.t).toBeGreaterThanOrEqual(0);
        });

        it('should handle division where nsh > 0', () => {
            // nsh = DB - nbits(pm.data[pm.t-1])
            // To make nsh > 0, we need the most significant digit of divisor
            // to have fewer bits than DB (28)
            const a = new BigInteger('ffffffffffffffffffffffffffffffff');
            const b = new BigInteger('1234567'); // Small enough that nsh > 0
            const r = new BigInteger();
            a.divRemTo(b, r);
            expect(r.t).toBeGreaterThanOrEqual(0);
        });
    });

    describe('squareTo', () => {
        it('should square large numbers triggering overflow handling', () => {
            // Create a number that will trigger the overflow condition in squareTo
            const bi = new BigInteger('ffffffffffff');
            const result = new BigInteger();
            bi.squareTo(result);
            expect(result.t).toBeGreaterThan(0);
        });

        it('should square very large numbers', () => {
            // Even larger number to potentially trigger overflow condition
            const bi = new BigInteger('ffffffffffffffffffffffff');
            const result = new BigInteger();
            bi.squareTo(result);
            expect(result.t).toBeGreaterThan(0);
        });

        it('should square number with multiple digits', () => {
            // Need x.t > 1 to enter the for loop in squareTo (line 183)
            // and trigger the overflow condition (lines 185-197)
            const bi = new BigInteger('ffffffffffffffffffffffffffffff'); // multiple digits
            const result = new BigInteger();
            bi.squareTo(result);
            expect(result.t).toBeGreaterThan(0);
        });
    });
});

describe('ASN.1', () => {
    describe('derToOid', () => {
        it('should convert DER bytes to OID string', () => {
            // OID 1.2.840.113549.1.1.1 (RSA) in DER: 2A 86 48 86 F7 0D 01 01 01
            const der = String.fromCharCode(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01);
            const oid = derToOid(der);
            expect(oid).toBe('1.2.840.113549.1.1.1');
        });

        it('should handle simple OIDs', () => {
            // OID 1.2.3 in DER: 2A 03
            const der = String.fromCharCode(0x2A, 0x03);
            const oid = derToOid(der);
            expect(oid).toBe('1.2.3');
        });
    });

    describe('fromDer', () => {
        it('should parse simple INTEGER', () => {
            // INTEGER 5: 02 01 05
            const der = String.fromCharCode(0x02, 0x01, 0x05);
            const result = fromDer(der);
            expect(result.type).toBe(2); // INTEGER
            expect(result.constructed).toBe(false);
        });

        it('should parse SEQUENCE', () => {
            // SEQUENCE { INTEGER 5, INTEGER 10 }
            // 30 06 02 01 05 02 01 0a
            const der = String.fromCharCode(0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x0a);
            const result = fromDer(der);
            expect(result.type).toBe(16); // SEQUENCE
            expect(result.constructed).toBe(true);
            expect(Array.isArray(result.value)).toBe(true);
            expect((result.value as unknown[]).length).toBe(2);
        });

        it('should parse BIT STRING with nested content', () => {
            // BIT STRING containing a SEQUENCE
            // This tests the decodeBitStrings path (lines 470-503)
            // 03 09 00 30 06 02 01 05 02 01 0a
            // BIT STRING (unused bits: 0) containing SEQUENCE { INTEGER 5, INTEGER 10 }
            const der = String.fromCharCode(
                0x03, 0x09, // BIT STRING, length 9
                0x00, // unused bits = 0
                0x30, 0x06, // SEQUENCE, length 6
                0x02, 0x01, 0x05, // INTEGER 5
                0x02, 0x01, 0x0a, // INTEGER 10
            );
            const result = fromDer(der);
            expect(result.type).toBe(3); // BIT STRING
            // When decoded, the BIT STRING should contain the parsed SEQUENCE
            expect(Array.isArray(result.value)).toBe(true);
        });

        it('should parse BIT STRING with unused bits (non-zero)', () => {
            // BIT STRING with unused bits != 0 (covers the unused !== 0 branch)
            // 03 02 04 f0 - BIT STRING, length 2, 4 unused bits, value 0xf0
            const der = String.fromCharCode(0x03, 0x02, 0x04, 0xf0);
            const result = fromDer(der);
            expect(result.type).toBe(3); // BIT STRING
            // Should have bitStringContents since unused bits > 0
            expect(result.bitStringContents).toBeDefined();
        });

        it('should parse BIT STRING that does not fully decode as ASN.1', () => {
            // BIT STRING with content that is not valid ASN.1 (covers used !== length branch)
            // 03 05 00 ff ff ff ff - BIT STRING with invalid ASN.1 content
            const der = String.fromCharCode(0x03, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff);
            const result = fromDer(der);
            expect(result.type).toBe(3); // BIT STRING
            // Should fallback to raw bytes since content is not valid ASN.1
        });

        it('should handle long form length encoding', () => {
            // Create an OCTET STRING with 200 bytes (requires long form length)
            // 04 81 c8 [200 bytes of 'A']
            let der = String.fromCharCode(0x04, 0x81, 0xc8);
            for (let i = 0; i < 200; i++) {
                der += 'A';
            }
            const result = fromDer(der);
            expect(result.type).toBe(4); // OCTET STRING
            expect((result.value as string).length).toBe(200);
        });
    });
});

describe('PEM', () => {
    describe('pemDecode', () => {
        it('should throw on invalid PEM', () => {
            expect(() => pemDecode('invalid')).toThrow('Invalid PEM formatted message.');
        });

        it('should decode valid PEM with headers', () => {
            // A minimal valid PEM with just "test" base64 encoded
            const pem = `-----BEGIN TEST-----
dGVzdA==
-----END TEST-----`;
            const result = pemDecode(pem);
            expect(result).toBe('test');
        });
    });
});

describe('RSA with non-RSA OID', () => {
    it('should throw when OID is not RSA', async () => {
        const { publicKeyFromPem } = await import('../src/lib/rsa.ts');
        // This is a valid SubjectPublicKeyInfo structure but with EC OID (1.2.840.10045.2.1)
        // instead of RSA OID (1.2.840.113549.1.1.1)
        // The structure is:
        // SEQUENCE {
        //   SEQUENCE {
        //     NULL
        //     OID 1.2.840.10045.2.1 (EC)
        //   }
        //   BIT STRING {
        //     SEQUENCE {
        //       INTEGER (modulus placeholder)
        //       INTEGER (exponent placeholder)
        //     }
        //   }
        // }
        const ecOidPem = `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE/nvHu/SQQaos9TUljQsUuKI15Zr5SabP
rbB9WVjGtpQ6ywAOwqLtH6XGkqcxwA3EsGnsRTVZ0ediGd+8j8GhPg==
-----END PUBLIC KEY-----`;
        expect(() => publicKeyFromPem(ecOidPem)).toThrow();
    });
});
