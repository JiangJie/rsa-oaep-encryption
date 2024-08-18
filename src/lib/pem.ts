/**
 * Javascript implementation of basic PEM (Privacy Enhanced Mail) algorithms.
 *
 * See: RFC 1421.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2013-2014 Digital Bazaar, Inc.
 *
 * A Forge PEM object has the following fields:
 *
 * type: identifies the type of message (eg: "RSA PRIVATE KEY").
 *
 * procType: identifies the type of processing performed on the message,
 *   it has two subfields: version and type, eg: 4,ENCRYPTED.
 *
 * contentDomain: identifies the type of content in the message, typically
 *   only uses the value: "RFC822".
 *
 * dekInfo: identifies the message encryption algorithm and mode and includes
 *   any parameters for the algorithm, it has two subfields: algorithm and
 *   parameters, eg: DES-CBC,F8143EDE5960C597.
 *
 * headers: contains all other PEM encapsulated headers -- where order is
 *   significant (for pairing data like recipient ID + key info).
 *
 * body: the binary-encoded body.
 */

import { decode64 } from './util.ts';

/**
 * Decodes (deserializes) all PEM messages found in the given string.
 *
 * @param pem the PEM-formatted string to decode.
 *
 * @return the PEM message objects in an array.
 */
export function pemDecode(pem: string): string {
    // split string into PEM messages (be lenient w/EOF on BEGIN line)
    const rMessage = /\s*-----BEGIN ([A-Z0-9- ]+)-----\r?\n?([\x21-\x7e\s]+?(?:\r?\n\r?\n))?([:A-Za-z0-9+/=\s]+?)-----END \1-----/g;
    const match = rMessage.exec(pem);
    if (!match) {
        throw new Error('Invalid PEM formatted message.');
    }

    return decode64(match[3]);
}
