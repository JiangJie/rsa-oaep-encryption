/**
 * Javascript implementation of Abstract Syntax Notation Number One.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2015 Digital Bazaar, Inc.
 *
 * An API for storing data using the Abstract Syntax Notation Number One
 * format using DER (Distinguished Encoding Rules) encoding. This encoding is
 * commonly used to store data for PKI, i.e. X.509 Certificates, and this
 * implementation exists for that purpose.
 *
 * Abstract Syntax Notation Number One (ASN.1) is used to define the abstract
 * syntax of information without restricting the way the information is encoded
 * for transmission. It provides a standard that allows for open systems
 * communication. ASN.1 defines the syntax of information data and a number of
 * simple data types as well as a notation for describing them and specifying
 * values for them.
 *
 * The RSA algorithm creates public and private keys that are often stored in
 * X.509 or PKCS#X formats -- which use ASN.1 (encoded in DER format). This
 * class provides the most basic functionality required to store and load DSA
 * keys that are encoded according to ASN.1.
 *
 * The most common binary encodings for ASN.1 are BER (Basic Encoding Rules)
 * and DER (Distinguished Encoding Rules). DER is just a subset of BER that
 * has stricter requirements for how data must be encoded.
 *
 * Each ASN.1 structure has a tag (a byte identifying the ASN.1 structure type)
 * and a byte array for the value of this ASN1 structure which may be data or a
 * list of ASN.1 structures.
 *
 * Each ASN.1 structure using BER is (Tag-Length-Value):
 *
 * | byte 0 | bytes X | bytes Y |
 * |--------|---------|----------
 * |  tag   | length  |  value  |
 *
 * ASN.1 allows for tags to be of "High-tag-number form" which allows a tag to
 * be two or more octets, but that is not supported by this class. A tag is
 * only 1 byte. Bits 1-5 give the tag number (ie the data type within a
 * particular 'class'), 6 indicates whether or not the ASN.1 value is
 * constructed from other ASN.1 values, and bits 7 and 8 give the 'class'. If
 * bits 7 and 8 are both zero, the class is UNIVERSAL. If only bit 7 is set,
 * then the class is APPLICATION. If only bit 8 is set, then the class is
 * CONTEXT_SPECIFIC. If both bits 7 and 8 are set, then the class is PRIVATE.
 * The tag numbers for the data types for the class UNIVERSAL are listed below:
 *
 * UNIVERSAL 0 Reserved for use by the encoding rules
 * UNIVERSAL 1 Boolean type
 * UNIVERSAL 2 Integer type
 * UNIVERSAL 3 Bitstring type
 * UNIVERSAL 4 Octetstring type
 * UNIVERSAL 5 Null type
 * UNIVERSAL 6 Object identifier type
 * UNIVERSAL 7 Object descriptor type
 * UNIVERSAL 8 External type and Instance-of type
 * UNIVERSAL 9 Real type
 * UNIVERSAL 10 Enumerated type
 * UNIVERSAL 11 Embedded-pdv type
 * UNIVERSAL 12 UTF8String type
 * UNIVERSAL 13 Relative object identifier type
 * UNIVERSAL 14-15 Reserved for future editions
 * UNIVERSAL 16 Sequence and Sequence-of types
 * UNIVERSAL 17 Set and Set-of types
 * UNIVERSAL 18-22, 25-30 Character string types
 * UNIVERSAL 23-24 Time types
 *
 * The length of an ASN.1 structure is specified after the tag identifier.
 * There is a definite form and an indefinite form. The indefinite form may
 * be used if the encoding is constructed and not all immediately available.
 * The indefinite form is encoded using a length byte with only the 8th bit
 * set. The end of the constructed object is marked using end-of-contents
 * octets (two zero bytes).
 *
 * The definite form looks like this:
 *
 * The length may take up 1 or more bytes, it depends on the length of the
 * value of the ASN.1 structure. DER encoding requires that if the ASN.1
 * structure has a value that has a length greater than 127, more than 1 byte
 * will be used to store its length, otherwise just one byte will be used.
 * This is strict.
 *
 * In the case that the length of the ASN.1 value is less than 127, 1 octet
 * (byte) is used to store the "short form" length. The 8th bit has a value of
 * 0 indicating the length is "short form" and not "long form" and bits 7-1
 * give the length of the data. (The 8th bit is the left-most, most significant
 * bit: also known as big endian or network format).
 *
 * In the case that the length of the ASN.1 value is greater than 127, 2 to
 * 127 octets (bytes) are used to store the "long form" length. The first
 * byte's 8th bit is set to 1 to indicate the length is "long form." Bits 7-1
 * give the number of additional octets. All following octets are in base 256
 * with the most significant digit first (typical big-endian binary unsigned
 * integer storage). So, for instance, if the length of a value was 257, the
 * first byte would be set to:
 *
 * 10000010 = 130 = 0x82.
 *
 * This indicates there are 2 octets (base 256) for the length. The second and
 * third bytes (the octets just mentioned) would store the length in base 256:
 *
 * octet 2: 00000001 = 1 * 256^1 = 256
 * octet 3: 00000001 = 1 * 256^0 = 1
 * total = 257
 *
 * The algorithm for converting a js integer value of 257 to base-256 is:
 *
 * const value = 257;
 * const bytes = [];
 * bytes[0] = (value >>> 8) & 0xFF; // most significant byte first
 * bytes[1] = value & 0xFF;        // least significant byte last
 *
 * On the ASN.1 UNIVERSAL Object Identifier (OID) type:
 *
 * An OID can be written like: "value1.value2.value3...valueN"
 *
 * The DER encoding rules:
 *
 * The first byte has the value 40 * value1 + value2.
 * The following bytes, if any, encode the remaining values. Each value is
 * encoded in base 128, most significant digit first (big endian), with as
 * few digits as possible, and the most significant bit of each byte set
 * to 1 except the last in each value's encoding. For example: Given the
 * OID "1.2.840.113549", its DER encoding is (remember each byte except the
 * last one in each encoding is OR'd with 0x80):
 *
 * byte 1: 40 * 1 + 2 = 42 = 0x2A.
 * bytes 2-3: 128 * 6 + 72 = 840 = 6 72 = 6 72 = 0x0648 = 0x8648
 * bytes 4-6: 16384 * 6 + 128 * 119 + 13 = 6 119 13 = 0x06770D = 0x86F70D
 *
 * The final value is: 0x2A864886F70D.
 * The full OID (including ASN.1 tag and length of 6 bytes) is:
 * 0x06062A864886F70D
 */

import { ByteStringBuffer } from './ByteStringBuffer.ts';

export interface ASN1 {
    constructed: boolean;
    tagClass: number;
    type: number;
    value: string | ASN1[],
    bitStringContents?: string;
}

interface Validator {
    constructed: boolean;
    tagClass: number;
    type: number;
    value?: Validator[];
}

/**
 * ASN.1 classes.
 */
const Class = {
    UNIVERSAL: 0x00,
    APPLICATION: 0x40,
    CONTEXT_SPECIFIC: 0x80,
    PRIVATE: 0xC0,
} as const;

/**
 * ASN.1 types. Not all types are supported by this implementation, only
 * those necessary to implement a simple PKI are implemented.
 */
const Type = {
    NONE: 0,
    BOOLEAN: 1,
    INTEGER: 2,
    BITSTRING: 3,
    OCTETSTRING: 4,
    NULL: 5,
    OID: 6,
    ODESC: 7,
    EXTERNAL: 8,
    REAL: 9,
    ENUMERATED: 10,
    EMBEDDED: 11,
    UTF8: 12,
    ROID: 13,
    SEQUENCE: 16,
    SET: 17,
    PRINTABLESTRING: 19,
    IA5STRING: 22,
    UTCTIME: 23,
    GENERALIZEDTIME: 24,
    BMPSTRING: 30,
} as const;

// validator for an RSA public key
const RSAPublicKeyValidator = {
    // RSAPublicKey
    // name: 'RSAPublicKey',
    tagClass: Class.UNIVERSAL,
    type: Type.SEQUENCE,
    constructed: true,
    value: [{
        // modulus (n)
        // name: 'RSAPublicKey.modulus',
        tagClass: Class.UNIVERSAL,
        type: Type.INTEGER,
        constructed: false,
        // capture: 'publicKeyModulus'
    }, {
        // publicExponent (e)
        // name: 'RSAPublicKey.exponent',
        tagClass: Class.UNIVERSAL,
        type: Type.INTEGER,
        constructed: false,
        // capture: 'publicKeyExponent'
    }]
};

// validator for an SubjectPublicKeyInfo structure
// Note: Currently only works with an RSA public key
const PublicKeyValidator = {
    // name: 'SubjectPublicKeyInfo',
    tagClass: Class.UNIVERSAL,
    type: Type.SEQUENCE,
    constructed: true,
    // captureAsn1: 'subjectPublicKeyInfo',
    value: [{
        // name: 'SubjectPublicKeyInfo.AlgorithmIdentifier',
        tagClass: Class.UNIVERSAL,
        type: Type.SEQUENCE,
        constructed: true,
        value: [{
            tagClass: Class.UNIVERSAL,
            type: Type.NULL,
            constructed: false,
        }, {
            // name: 'AlgorithmIdentifier.algorithm',
            tagClass: Class.UNIVERSAL,
            type: Type.OID,
            constructed: false,
            // capture: 'publicKeyOid'
        }]
    }, {
        // subjectPublicKey
        // name: 'SubjectPublicKeyInfo.subjectPublicKey',
        tagClass: Class.UNIVERSAL,
        type: Type.BITSTRING,
        constructed: false,
        value: [{
            // RSAPublicKey
            // name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey',
            tagClass: Class.UNIVERSAL,
            type: Type.SEQUENCE,
            constructed: true,
            // optional: true,
            // captureAsn1: 'rsaPublicKey'
        }]
    }]
};

/**
 * Deconstructing a public key from an ASN.1 object.
 * @param obj the ASN.1 object to deconstruct.
 * @returns publicKeyOid and rsaPublicKey or null when the object is invalid.
 */
export function deconstructPublicKey(obj: ASN1) {
    if (validate(obj, PublicKeyValidator) && PublicKeyValidator.value.every((x, i) => {
        return validate(obj.value[i] as ASN1, x);
    })) {
        return {
            publicKeyOid: ((obj.value[0] as ASN1).value[0] as ASN1).value as string,
            rsaPublicKey: (obj.value[1] as ASN1).value[0] as ASN1,
        };
    }

    return null;
}

/**
 * Deconstructing a RSA public key from an ASN.1 object.
 * @param obj the ASN.1 object to deconstruct.
 * @returns publicKeyModulus and publicKeyExponent or null when the object is invalid.
 */
export function deconstructRSAPublicKey(obj: ASN1) {
    if (validate(obj, RSAPublicKeyValidator) && RSAPublicKeyValidator.value.every((x, i) => {
        return validate(obj.value[i] as ASN1, x);
    })) {
        return {
            publicKeyModulus: (obj.value[0] as ASN1).value as string,
            publicKeyExponent: (obj.value[1] as ASN1).value as string,
        };
    }

    return null;
}

/**
 * Validates that the given ASN.1 object is at least a super set of the
 * given ASN.1 structure. Only tag classes and types are checked. An
 * optional map may also be provided to capture ASN.1 values while the
 * structure is checked.
 *
 * To capture an ASN.1 value, set an object in the validator's 'capture'
 * parameter to the key to use in the capture map. To capture the full
 * ASN.1 object, specify 'captureAsn1'. To capture BIT STRING bytes, including
 * the leading unused bits counter byte, specify 'captureBitStringContents'.
 * To capture BIT STRING bytes, without the leading unused bits counter byte,
 * specify 'captureBitStringValue'.
 *
 * Objects in the validator may set a field 'optional' to true to indicate
 * that it isn't necessary to pass validation.
 *
 * @param obj the ASN.1 object to validate.
 * @param v the ASN.1 structure validator.
 *
 * @return true on success, false on failure.
 */
function validate(obj: ASN1, v: Validator): boolean {
    return obj.tagClass === v.tagClass
        && obj.type === v.type
        // ensure constructed flag is the same if specified
        && obj.constructed === v.constructed
        && (!v.value || obj.value.length === v.value.length);
}

/**
 * Parses an asn1 object from a byte buffer in DER format.
 *
 * @param bytes the byte buffer to parse from.
 * @param [strict] true to be strict when checking value lengths, false to
 *          allow truncated values (default: true).
 * @param [options] object with options or boolean strict flag
 *          [strict] true to be strict when checking value lengths, false to
 *            allow truncated values (default: true).
 *          [decodeBitStrings] true to attempt to decode the content of
 *            BIT STRINGs (not OCTET STRINGs) using strict mode. Note that
 *            without schema support to understand the data context this can
 *            erroneously decode values that happen to be valid ASN.1. This
 *            flag will be deprecated or removed as soon as schema support is
 *            available. (default: true)
 *
 * @throws Will throw an error for various malformed input conditions.
 *
 * @return the parsed asn1 object.
 */
export function fromDer(bytes: string): ASN1 {
    const value = _fromDer(new ByteStringBuffer(bytes), 0, {
        strict: true,
        decodeBitStrings: true,
    });
    return value;
}

/**
 * Converts a DER-encoded byte buffer to an OID dot-separated string. The
 * byte buffer should contain only the DER-encoded value, not any tag or
 * length bytes.
 *
 * @param bytes the byte buffer.
 *
 * @return the OID dot-separated string.
 */
export function derToOid(bytes: string): string {
    const buffer = new ByteStringBuffer(bytes);

    // first byte is 40 * value1 + value2
    let b = buffer.getByte();
    let oid = Math.floor(b / 40) + '.' + (b % 40);

    // other bytes are each value in base 128 with 8th bit set except for
    // the last byte for each value
    let value = 0;
    while (buffer.length() > 0) {
        b = buffer.getByte();
        value = value << 7;
        // not the last byte for the value
        if (b & 0x80) {
            value += b & 0x7F;
        } else {
            // last byte
            oid += '.' + (value + b);
            value = 0;
        }
    }

    return oid;
}

/**
 * Gets the length of a BER-encoded ASN.1 value.
 *
 * In case the length is not specified, undefined is returned.
 *
 * @param bytes the byte buffer to parse from.
 *
 * @return the length of the BER-encoded ASN.1 value or undefined.
 */
function _getValueLength(bytes: ByteStringBuffer): number {
    // TODO: move this function and related DER/BER functions to a der.js
    // file; better abstract ASN.1 away from der/ber.
    // fromDer already checked that this byte exists
    const b2 = bytes.getByte();

    // see if the length is "short form" or "long form" (bit 8 set)
    let length: number;
    const longForm = b2 & 0x80;
    if (!longForm) {
        // length is just the first byte
        length = b2;
    } else {
        // the number of bytes the length is specified in bits 7 through 1
        // and each length byte is in big-endian base-256
        const longFormBytes = b2 & 0x7F;
        // bypass tsc error
        length = bytes.getInt(longFormBytes << 3 as 8);
    }
    return length;
}

/**
 * Internal function to parse an asn1 object from a byte buffer in DER format.
 *
 * @param bytes the byte buffer to parse from.
 * @param depth the current parsing depth.
 * @param options object with same options as fromDer().
 *
 * @return the parsed asn1 object.
 */
function _fromDer(bytes: ByteStringBuffer, depth: number, options: {
    strict: boolean;
    decodeBitStrings: boolean;
}): ASN1 {
    // get the first byte
    const b1 = bytes.getByte();

    // get the tag class
    const tagClass = (b1 & 0xC0);

    // get the type (bits 1-5)
    const type = b1 & 0x1F;

    // get the variable value length and adjust remaining bytes
    let start = bytes.length();
    let length = _getValueLength(bytes);

    // value storage
    let value: string | ASN1[] | undefined;
    // possible BIT STRING contents storage
    let bitStringContents: string | undefined;

    // constructed flag is bit 6 (32 = 0x20) of the first byte
    const constructed = ((b1 & 0x20) === 0x20);
    if (constructed) {
        // parse child asn1 objects from the value
        value = [];
        // parsing asn1 object of definite length
        while (length > 0) {
            start = bytes.length();
            value.push(_fromDer(bytes, depth + 1, options));
            length -= start - bytes.length();
        }
    }

    // if a BIT STRING, save the contents including padding
    if (value === undefined && tagClass === Class.UNIVERSAL &&
        type === Type.BITSTRING) {
        bitStringContents = bytes.bytes(length);
    }

    // determine if a non-constructed value should be decoded as a composed
    // value that contains other ASN.1 objects. BIT STRINGs (and OCTET STRINGs)
    // can be used this way.
    if (value === undefined && options.decodeBitStrings &&
        tagClass === Class.UNIVERSAL &&
        // FIXME: OCTET STRINGs not yet supported here
        // .. other parts of forge expect to decode OCTET STRINGs manually
        (type === Type.BITSTRING /*|| type === Type.OCTETSTRING*/) &&
        length > 1) {
        // save read position
        let unused = 0;
        if (type === Type.BITSTRING) {
            unused = bytes.getByte();
        }
        // if all bits are used, maybe the BIT/OCTET STRING holds ASN.1 objs
        if (unused === 0) {
            // attempt to parse child asn1 object from the value
            // (stored in array to signal composed value)
            start = bytes.length();
            const subOptions = {
                // enforce strict mode to avoid parsing ASN.1 from plain data
                strict: true,
                decodeBitStrings: true
            };
            const composed = _fromDer(bytes, depth + 1, subOptions);
            let used = start - bytes.length();
            if (type === Type.BITSTRING) {
                used++;
            }

            // if the data all decoded and the class indicates UNIVERSAL or
            // CONTEXT_SPECIFIC then assume we've got an encapsulated ASN.1 object
            if (used === length) {
                value = [composed];
            }
        }
    }

    if (value === undefined) {
        // asn1 not constructed or composed, get raw value
        // TODO: do DER to OID conversion and vice-versa in .toDer?

        value = bytes.getBytes(length);
    }

    // add BIT STRING contents if available
    // create and return asn1 object
    return create(tagClass, type, constructed, value, bitStringContents);
}

/**
 * Creates a new asn1 object.
 *
 * @param tagClass the tag class for the object.
 * @param type the data type (tag number) for the object.
 * @param constructed true if the asn1 object is in constructed form.
 * @param value the value for the object, if it is not constructed.
 * @param [options] the options to use:
 *          [bitStringContents] the plain BIT STRING content including padding
 *            byte.
 *
 * @return the asn1 object.
 */
function create(tagClass: number, type: number, constructed: boolean, value: string | ASN1[], bitStringContents?: string): ASN1 {
    /* An asn1 object has a tagClass, a type, a constructed flag, and a
      value. The value's type depends on the constructed flag. If
      constructed, it will contain a list of other asn1 objects. If not,
      it will contain the ASN.1 value as an array of bytes formatted
      according to the ASN.1 data type. */

    // remove undefined values
    if (Array.isArray(value)) {
        value = value.filter(x => x != null);
    }

    const obj: ASN1 = {
        constructed,
        tagClass,
        type,
        value,
    };
    if (bitStringContents) {
        obj.bitStringContents = bitStringContents;
    }
    return obj;
}
