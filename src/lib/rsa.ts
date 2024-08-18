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

import { deconstructPublicKey, deconstructRSAPublicKey, derToOid, fromDer, type ASN1 } from './asn1.ts';
import { ByteStringBuffer } from './ByteStringBuffer.ts';
import { BigInteger } from './jsbn.ts';
import { pemDecode } from './pem.ts';
import { encode_rsa_oaep, type RSAEncodeOptions } from './pkcs1.ts';

export interface RSAKey {
    n: BigInteger;
    e: BigInteger;
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
function rsaEncrypt(m: string, key: RSAKey): ArrayBuffer {
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
 * Sets an RSA public key from BigIntegers modulus and exponent.
 *
 * @param n the modulus.
 * @param e the exponent.
 *
 * @return the public key.
 */
function setRsaPublicKey(n: BigInteger, e: BigInteger) {
    const key: RSAKey = {
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
