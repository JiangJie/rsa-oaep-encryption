/**
 * Javascript implementation of basic RSA algorithms.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2014 Digital Bazaar, Inc.
 *
 * The only algorithm currently supported for PKI is RSA.
 *
 * An RSA key is often stored in ASN.1 DER format. The SubjectPublicKeyInfo
 * ASN.1 structure is composed of an algorithm of type AlgorithmIdentifier
 * and a subjectPublicKey of type bit string.
 *
 * The AlgorithmIdentifier contains an Object Identifier (OID) and parameters
 * for the algorithm, if any. In the case of RSA, there aren't any.
 *
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm AlgorithmIdentifier,
 *   subjectPublicKey BIT STRING
 * }
 *
 * AlgorithmIdentifer ::= SEQUENCE {
 *   algorithm OBJECT IDENTIFIER,
 *   parameters ANY DEFINED BY algorithm OPTIONAL
 * }
 *
 * For an RSA public key, the subjectPublicKey is:
 *
 * RSAPublicKey ::= SEQUENCE {
 *   modulus            INTEGER,    -- n
 *   publicExponent     INTEGER     -- e
 * }
 *
 * PrivateKeyInfo ::= SEQUENCE {
 *   version                   Version,
 *   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
 *   privateKey                PrivateKey,
 *   attributes           [0]  IMPLICIT Attributes OPTIONAL
 * }
 *
 * Version ::= INTEGER
 * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
 * PrivateKey ::= OCTET STRING
 * Attributes ::= SET OF Attribute
 *
 * An RSA private key as the following structure:
 *
 * RSAPrivateKey ::= SEQUENCE {
 *   version Version,
 *   modulus INTEGER, -- n
 *   publicExponent INTEGER, -- e
 *   privateExponent INTEGER, -- d
 *   prime1 INTEGER, -- p
 *   prime2 INTEGER, -- q
 *   exponent1 INTEGER, -- d mod (p-1)
 *   exponent2 INTEGER, -- d mod (q-1)
 *   coefficient INTEGER -- (inverse of q) mod p
 * }
 *
 * Version ::= INTEGER
 *
 * The OID for the RSA key algorithm is: 1.2.840.113549.1.1.1
 */

/*
 * RSA encryption and decryption, see RFC 2313.
 */

import {
    deconstructPrivateKey,
    deconstructPublicKey,
    deconstructRSAPrivateKey,
    deconstructRSAPublicKey,
    derToOid,
    fromDer,
    type ASN1,
} from './asn1.ts';
import { ByteStringBuffer } from './ByteStringBuffer.ts';
import { BigInteger, BigIntegerONE } from './jsbn.ts';
import { pemDecode } from './pem.ts';
import { decode_rsa_oaep, encode_rsa_oaep, type RSAEncodeOptions } from './pkcs1.ts';
import { random } from './random.ts';

export interface RSAPublicKey {
    n: BigInteger;
    e: BigInteger;
}

export interface RSAPrivateKey {
    n: BigInteger;
    e: BigInteger;
    d: BigInteger;
    p: BigInteger;
    q: BigInteger;
    dP: BigInteger;
    dQ: BigInteger;
    qInv: BigInteger;
}

const RSAPublicKeyIOD = '1.2.840.113549.1.1.1' as const;

/**
 * NOTE: THIS METHOD IS DEPRECATED, use 'sign' on a private key object or
 * 'encrypt' on a public key object instead.
 *
 * Performs RSA encryption.
 *
 * The parameter bt controls whether to put padding bytes before the
 * message passed in. Set bt to either true or false to disable padding
 * completely (in order to handle e.g. EMSA-PSS encoding seperately before),
 * signaling whether the encryption operation is a public key operation
 * (i.e. encrypting data) or not, i.e. private key operation (data signing).
 *
 * For PKCS#1 v1.5 padding pass in the block type to use, i.e. either 0x01
 * (for signing) or 0x02 (for encryption). The key operation mode (private
 * or public) is derived from this flag in that case).
 *
 * @param m the message to encrypt as a byte string.
 * @param key the RSA key to use.
 *
 * @return the encrypted bytes as a string.
 */
function rsaEncrypt(m: string, key: RSAPublicKey): ArrayBuffer {
    // get the length of the modulus in bytes
    const k = Math.ceil(key.n.bitLength() / 8);

    const eb = new ByteStringBuffer();
    eb.putBytes(m);

    // load encryption block as big integer 'x'
    // FIXME: hex conversion inefficient, get BigInteger w/byte strings
    const x = new BigInteger(eb.toHex());

    // do RSA encryption
    const y = x.modPow(key.e, key.n);

    // convert y into the encrypted data byte string, if y is shorter in
    // bytes than k, then prepend zero bytes to fill up ed
    // FIXME: hex conversion inefficient, get BigInteger w/byte strings
    const yhex = y.toString();
    const ab = new ArrayBuffer(k);
    const u8a = new Uint8Array(ab);
    let zeros = k - Math.ceil(yhex.length / 2);
    const prependedLength = zeros;
    while (zeros > 0) {
        u8a[prependedLength - zeros] = 0;
        --zeros;
    }
    let i = 0;
    if ((yhex.length & 1) === 1) {
        // odd number of characters, convert first character alone
        i = 1;
        u8a[prependedLength] = parseInt(yhex[0], 16);
    }
    // convert 2 characters (1 byte) at a time
    for (; i < yhex.length; i += 2) {
        u8a[prependedLength + Math.ceil(i / 2)] = parseInt(yhex.substr(i, 2), 16);
    }

    return ab;
}

/**
 * Performs x^c mod n (RSA decryption operation).
 *
 * @param x the number to raise and mod.
 * @param key the key to use.
 *
 * @return the result of x^c mod n.
 */
function modPowPrivate(x: BigInteger, key: RSAPrivateKey) {
    if (!key.p || !key.q) {
        // allow calculation without CRT params (slow)
        return x.modPow(key.d, key.n);
    }

    // pre-compute dP, dQ, and qInv if necessary
    if (!key.dP) {
        key.dP = key.d.mod(key.p.subtract(BigIntegerONE));
    }
    if (!key.dQ) {
        key.dQ = key.d.mod(key.q.subtract(BigIntegerONE));
    }
    if (!key.qInv) {
        key.qInv = key.q.modInverse(key.p);
    }

    /* Chinese remainder theorem (CRT) states:

      Suppose n1, n2, ..., nk are positive integers which are pairwise
      coprime (n1 and n2 have no common factors other than 1). For any
      integers x1, x2, ..., xk there exists an integer x solving the
      system of simultaneous congruences (where ~= means modularly
      congruent so a ~= b mod n means a mod n = b mod n):

      x ~= x1 mod n1
      x ~= x2 mod n2
      ...
      x ~= xk mod nk

      This system of congruences has a single simultaneous solution x
      between 0 and n - 1. Furthermore, each xk solution and x itself
      is congruent modulo the product n = n1*n2*...*nk.
      So x1 mod n = x2 mod n = xk mod n = x mod n.

      The single simultaneous solution x can be solved with the following
      equation:

      x = sum(xi*ri*si) mod n where ri = n/ni and si = ri^-1 mod ni.

      Where x is less than n, xi = x mod ni.

      For RSA we are only concerned with k = 2. The modulus n = pq, where
      p and q are coprime. The RSA decryption algorithm is:

      y = x^d mod n

      Given the above:

      x1 = x^d mod p
      r1 = n/p = q
      s1 = q^-1 mod p
      x2 = x^d mod q
      r2 = n/q = p
      s2 = p^-1 mod q

      So y = (x1r1s1 + x2r2s2) mod n
           = ((x^d mod p)q(q^-1 mod p) + (x^d mod q)p(p^-1 mod q)) mod n

      According to Fermat's Little Theorem, if the modulus P is prime,
      for any integer A not evenly divisible by P, A^(P-1) ~= 1 mod P.
      Since A is not divisible by P it follows that if:
      N ~= M mod (P - 1), then A^N mod P = A^M mod P. Therefore:

      A^N mod P = A^(M mod (P - 1)) mod P. (The latter takes less effort
      to calculate). In order to calculate x^d mod p more quickly the
      exponent d mod (p - 1) is stored in the RSA private key (the same
      is done for x^d mod q). These values are referred to as dP and dQ
      respectively. Therefore we now have:

      y = ((x^dP mod p)q(q^-1 mod p) + (x^dQ mod q)p(p^-1 mod q)) mod n

      Since we'll be reducing x^dP by modulo p (same for q) we can also
      reduce x by p (and q respectively) before hand. Therefore, let

      xp = ((x mod p)^dP mod p), and
      xq = ((x mod q)^dQ mod q), yielding:

      y = (xp*q*(q^-1 mod p) + xq*p*(p^-1 mod q)) mod n

      This can be further reduced to a simple algorithm that only
      requires 1 inverse (the q inverse is used) to be used and stored.
      The algorithm is called Garner's algorithm. If qInv is the
      inverse of q, we simply calculate:

      y = (qInv*(xp - xq) mod p) * q + xq

      However, there are two further complications. First, we need to
      ensure that xp > xq to prevent signed BigIntegers from being used
      so we add p until this is true (since we will be mod'ing with
      p anyway). Then, there is a known timing attack on algorithms
      using the CRT. To mitigate this risk, "cryptographic blinding"
      should be used. This requires simply generating a random number r
      between 0 and n-1 and its inverse and multiplying x by r^e before
      calculating y and then multiplying y by r^-1 afterwards. Note that
      r must be coprime with n (gcd(r, n) === 1) in order to have an
      inverse.
    */

    // cryptographic blinding
    let r;
    do {
        r = new BigInteger(new ByteStringBuffer(random.generateSync(key.n.bitLength() / 8)).toHex());
    } while (r.compareTo(key.n) >= 0 || !r.gcd(key.n).equals(BigIntegerONE));
    x = x.multiply(r.modPow(key.e, key.n)).mod(key.n);

    // calculate xp and xq
    let xp = x.mod(key.p).modPow(key.dP, key.p);
    const xq = x.mod(key.q).modPow(key.dQ, key.q);

    // xp must be larger than xq to avoid signed bit usage
    while (xp.compareTo(xq) < 0) {
        xp = xp.add(key.p);
    }

    // do last step
    let y = xp.subtract(xq).multiply(key.qInv).mod(key.p).multiply(key.q).add(xq);

    // remove effect of random for cryptographic blinding
    y = y.multiply(r.modInverse(key.n)).mod(key.n);

    return y;
}

/**
 * NOTE: THIS METHOD IS DEPRECATED, use 'decrypt' on a private key object or
 * 'verify' on a public key object instead.
 *
 * Performs RSA decryption.
 *
 * The parameter ml controls whether to apply PKCS#1 v1.5 padding
 * or not.  Set ml = false to disable padding removal completely
 * (in order to handle e.g. EMSA-PSS later on) and simply pass back
 * the RSA encryption block.
 *
 * @param ed the encrypted data to decrypt in as a byte string.
 * @param key the RSA key to use.
 *
 * @return the decrypted message as a string
 */
function rsaDecrypt(ed: string, key: RSAPrivateKey): string {
    // get the length of the modulus in bytes
    const k = Math.ceil(key.n.bitLength() / 8);

    // error if the length of the encrypted data ED is not k
    if (ed.length !== k) {
        throw new Error(`Encrypted message length is invalid. length=${ed.length} expected=${k}`);
    }

    // convert encrypted data into a big integer
    // FIXME: hex conversion inefficient, get BigInteger w/byte strings
    const y = new BigInteger(new ByteStringBuffer(ed).toHex());

    // y must be less than the modulus or it wasn't the result of
    // a previous mod operation (encryption) using that modulus
    if (y.compareTo(key.n) >= 0) {
        throw new Error('Encrypted message is invalid.');
    }

    // do RSA decryption
    const x = modPowPrivate(y, key);

    // create the encryption block, if x is shorter in bytes than k, then
    // prepend zero bytes to fill up eb
    // FIXME: hex conversion inefficient, get BigInteger w/byte strings
    const xhex = x.toString();
    const u8a = new Uint8Array(new ArrayBuffer(k));
    let zeros = k - Math.ceil(xhex.length / 2);
    const prependedLength = zeros;
    while (zeros > 0) {
        u8a[prependedLength - zeros] = 0;
        --zeros;
    }
    let i = 0;
    if ((xhex.length & 1) === 1) {
        // odd number of characters, convert first character alone
        i = 1;
        u8a[prependedLength] = parseInt(xhex[0], 16);
    }
    // convert 2 characters (1 byte) at a time
    for (; i < xhex.length; i += 2) {
        u8a[prependedLength + Math.ceil(i / 2)] = parseInt(xhex.substr(i, 2), 16);
    }

    // Uint8Array to string
    let output = '';

    for (let i = 0; i < u8a.length; i++) {
        output += String.fromCharCode(u8a[i]);
    }

    return output;
}

/**
 * Sets an RSA public key from BigIntegers modulus and exponent.
 *
 * @param n the modulus.
 * @param e the exponent.
 *
 * @return the public key.
 */
function setRsaPublicKey(n: BigInteger, e: BigInteger) {
    const key: RSAPublicKey = {
        n: n,
        e: e,
    };

    return {
        /**
         * Encrypts the given data with this public key. Newer applications
         * should use the 'RSA-OAEP' decryption scheme, 'RSAES-PKCS1-V1_5' is for
         * legacy applications.
         *
         * @param data the byte string to encrypt.
         * @param schemeOptions any scheme-specific options.
         *
         * @return the encrypted byte string.
         */
        encrypt(data: string, schemeOptions: RSAEncodeOptions): ArrayBuffer {
            // do scheme-based encoding then rsa encryption
            const e = encode_rsa_oaep(key.n, data, schemeOptions);
            return rsaEncrypt(e, key);
        },
    };
}

/**
 * Sets an RSA private key from BigIntegers modulus, exponent, primes,
 * prime exponents, and modular multiplicative inverse.
 *
 * @param n the modulus.
 * @param e the public exponent.
 * @param d the private exponent ((inverse of e) mod n).
 * @param p the first prime.
 * @param q the second prime.
 * @param dP exponent1 (d mod (p-1)).
 * @param dQ exponent2 (d mod (q-1)).
 * @param qInv ((inverse of q) mod p)
 *
 * @return the private key.
 */
function setRsaPrivateKey(
    n: BigInteger,
    e: BigInteger,
    d: BigInteger,
    p: BigInteger,
    q: BigInteger,
    dP: BigInteger,
    dQ: BigInteger,
    qInv: BigInteger
) {
    const key: RSAPrivateKey = {
        n: n,
        e: e,
        d: d,
        p: p,
        q: q,
        dP: dP,
        dQ: dQ,
        qInv: qInv,
    };

    return {
        /**
         * Decrypts the given data with this private key. Newer applications
         * should use the 'RSA-OAEP' decryption scheme, 'RSAES-PKCS1-V1_5' is for
         * legacy applications.
         *
         * @param data the byte string to decrypt.
         * @param schemeOptions any scheme-specific options.
         *
         * @return the decrypted byte string.
         */
        decrypt(data: string, schemeOptions: RSAEncodeOptions): string {
            // do rsa decryption then scheme-based decoding
            const d = rsaDecrypt(data, key);

            return decode_rsa_oaep(key.n, d, schemeOptions);
        },
    };
}

/**
 * Converts a public key from an ASN.1 SubjectPublicKeyInfo or RSAPublicKey.
 *
 * @param obj the asn1 representation of a SubjectPublicKeyInfo or RSAPublicKey.
 *
 * @return the public key.
 */
function publicKeyFromAsn1(obj: ASN1) {
    // get SubjectPublicKeyInfo
    const publicKey = deconstructPublicKey(obj);
    if (!publicKey) {
        throw new Error('Invalid RSAPublicKey.');
    }

    if (derToOid(publicKey.publicKeyOid) !== RSAPublicKeyIOD) {
        throw new Error('Cannot read public key. Unknown OID.');
    }

    // get RSA params
    const rsaPublicKey = deconstructRSAPublicKey(publicKey.rsaPublicKey);
    if (!rsaPublicKey) {
        throw new Error('ASN.1 object does not contain an RSAPublicKey.');
    }

    // FIXME: inefficient, get a BigInteger that uses byte strings
    const n = new ByteStringBuffer(rsaPublicKey.publicKeyModulus).toHex();
    const e = new ByteStringBuffer(rsaPublicKey.publicKeyExponent).toHex();

    // set public key
    return setRsaPublicKey(new BigInteger(n), new BigInteger(e));
}

/**
 * Converts a private key from an ASN.1 SubjectPrivateKeyInfo or RSAPrivateKey.
 *
 * @param obj the asn1 representation of a SubjectPrivateKeyInfo or RSAPrivateKey.
 *
 * @return the private key.
 */
function privateKeyFromAsn1(obj: ASN1) {
    // get PrivateKeyInfo
    const privateKey = deconstructPrivateKey(obj);
    if (!privateKey) {
        throw new Error('Invalid RSAPrivateKey.');
    }

    const asnPrivateKey = fromDer(privateKey.privateKey);

    // get RSAPrivateKey
    const rsaPrivateKey = deconstructRSAPrivateKey(asnPrivateKey);
    if (!rsaPrivateKey) {
        throw new Error('ASN.1 object does not contain an RSAPrivateKey.');
    }

    // Note: Version is currently ignored.
    // capture.privateKeyVersion
    // FIXME: inefficient, get a BigInteger that uses byte strings
    const n = new ByteStringBuffer(rsaPrivateKey.privateKeyModulus).toHex();
    const e = new ByteStringBuffer(rsaPrivateKey.privateKeyPublicExponent).toHex();
    const d = new ByteStringBuffer(rsaPrivateKey.privateKeyPrivateExponent).toHex();
    const p = new ByteStringBuffer(rsaPrivateKey.privateKeyPrime1).toHex();
    const q = new ByteStringBuffer(rsaPrivateKey.privateKeyPrime2).toHex();
    const dP = new ByteStringBuffer(rsaPrivateKey.privateKeyExponent1).toHex();
    const dQ = new ByteStringBuffer(rsaPrivateKey.privateKeyExponent2).toHex();
    const qInv = new ByteStringBuffer(rsaPrivateKey.privateKeyCoefficient).toHex();

    // set private key
    return setRsaPrivateKey(
        new BigInteger(n),
        new BigInteger(e),
        new BigInteger(d),
        new BigInteger(p),
        new BigInteger(q),
        new BigInteger(dP),
        new BigInteger(dQ),
        new BigInteger(qInv)
    );
}

/**
 * Converts an RSA public key from PEM format.
 *
 * @param pemKey the PEM-formatted public key.
 *
 * @return the public key.
 */
export function publicKeyFromPem(pemKey: string) {
    const body = pemDecode(pemKey);

    // convert DER to ASN.1 object
    const obj = fromDer(body);

    return publicKeyFromAsn1(obj);
}

/**
 * Converts an RSA private key from PEM format.
 *
 * @param pemKey the PEM-formatted private key.
 *
 * @return the private key.
 */
export function privateKeyFromPem(pemKey: string) {
    const body = pemDecode(pemKey);

    // convert DER to ASN.1 object
    const obj = fromDer(body);

    return privateKeyFromAsn1(obj);
}
