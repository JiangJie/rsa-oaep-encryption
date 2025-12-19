# RSA-OAEP Encryption

[![License](https://img.shields.io/npm/l/rsa-oaep-encryption.svg)](LICENSE)
[![Build Status](https://github.com/JiangJie/rsa-oaep-encryption/actions/workflows/test.yml/badge.svg)](https://github.com/JiangJie/rsa-oaep-encryption/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/JiangJie/rsa-oaep-encryption/graph/badge.svg)](https://codecov.io/gh/JiangJie/rsa-oaep-encryption)
[![NPM version](https://img.shields.io/npm/v/rsa-oaep-encryption.svg)](https://npmjs.org/package/rsa-oaep-encryption)
[![NPM downloads](https://badgen.net/npm/dm/rsa-oaep-encryption)](https://npmjs.org/package/rsa-oaep-encryption)
[![JSR Version](https://jsr.io/badges/@happy-js/rsa-oaep-encryption)](https://jsr.io/@happy-js/rsa-oaep-encryption)
[![JSR Score](https://jsr.io/badges/@happy-js/rsa-oaep-encryption/score)](https://jsr.io/@happy-js/rsa-oaep-encryption/score)

A pure JavaScript/TypeScript implementation of RSA-OAEP encryption for environments without [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) support.

## Features

- **Pure JavaScript** - No native dependencies, works in any JavaScript runtime
- **TypeScript** - Full type definitions included
- **Web Crypto Compatible** - Returns `ArrayBuffer`, matching Web Crypto API output
- **Tree-shakeable** - Only import what you need
- **~100% Test Coverage** - Thoroughly tested against Web Crypto API

## Supported Algorithms

| Encryption | Hash Algorithms |
|------------|-----------------|
| RSA-OAEP | SHA-1, SHA-256, SHA-384, SHA-512 |

> **Note**: PKCS1-v1_5 padding is not supported. Only RSA-OAEP is available.

## Installation

```sh
# npm
npm install rsa-oaep-encryption

# yarn
yarn add rsa-oaep-encryption

# pnpm
pnpm add rsa-oaep-encryption

# JSR (Deno)
deno add @happy-js/rsa-oaep-encryption

# JSR (Bun)
bunx jsr add @happy-js/rsa-oaep-encryption
```

## Quick Start

```ts
import { importPublicKey, sha256 } from 'rsa-oaep-encryption';

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----`;

const encryptedData = importPublicKey(PUBLIC_KEY).encrypt('Hello, World!', sha256.create());
// encryptedData is ArrayBuffer
```

## Examples

### Basic Encryption

```ts
import { importPublicKey, sha1, sha256, sha384, sha512 } from 'rsa-oaep-encryption';

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----`;

const publicKey = importPublicKey(PUBLIC_KEY);

// Using different hash algorithms
const encrypted1 = publicKey.encrypt('data', sha1.create());    // SHA-1
const encrypted2 = publicKey.encrypt('data', sha256.create());  // SHA-256 (recommended)
const encrypted3 = publicKey.encrypt('data', sha384.create());  // SHA-384
const encrypted4 = publicKey.encrypt('data', sha512.create());  // SHA-512
```

### Convert to Base64 for Transmission

```ts
import { importPublicKey, sha256 } from 'rsa-oaep-encryption';

function arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----`;

const encryptedBuffer = importPublicKey(PUBLIC_KEY).encrypt('sensitive data', sha256.create());
const encryptedBase64 = arrayBufferToBase64(encryptedBuffer);

// Send encryptedBase64 to server
console.log(encryptedBase64);
```

### Server-side Decryption (Node.js with Web Crypto)

```ts
import { webcrypto } from 'node:crypto';

const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASC...
-----END PRIVATE KEY-----`;

async function decrypt(encryptedBase64: string): Promise<string> {
    // Convert Base64 to ArrayBuffer
    const encryptedData = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

    // Import private key
    const pemContent = PRIVATE_KEY.replace(/(-----(BEGIN|END) PRIVATE KEY-----|\s)/g, '');
    const keyData = Uint8Array.from(atob(pemContent), c => c.charCodeAt(0));

    const privateKey = await webcrypto.subtle.importKey(
        'pkcs8',
        keyData,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['decrypt']
    );

    // Decrypt
    const decryptedBuffer = await webcrypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        privateKey,
        encryptedData
    );

    return new TextDecoder().decode(decryptedBuffer);
}

// Usage
const decrypted = await decrypt(encryptedBase64);
console.log(decrypted); // 'sensitive data'
```

### Standalone SHA Hashing

Use the exported SHA functions independently for hashing:

```ts
import { sha1, sha256, sha384, sha512 } from 'rsa-oaep-encryption';

// Create hash and get hex string
const hash = sha256.create().update('Hello, World!').digest().toHex();
console.log(hash); // 'dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f'

// Incremental hashing
const hasher = sha256.create();
hasher.update('Hello, ');
hasher.update('World!');
const result = hasher.digest().toHex();

// Get raw bytes
const rawBytes = sha256.create().update('data').digest().bytes();

// Get ArrayBuffer (Web Crypto compatible)
const buffer = sha256.create().update('data').digest().toArrayBuffer();
```

### Web Crypto API Equivalent

This library's output is compatible with Web Crypto API. Here's the equivalent code:

**Using this library:**
```ts
import { importPublicKey, sha256 } from 'rsa-oaep-encryption';

const encrypted = importPublicKey(PUBLIC_KEY).encrypt('data', sha256.create());
```

**Using Web Crypto API:**
```ts
const pemContent = PUBLIC_KEY.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\s)/g, '');
const keyData = Uint8Array.from(atob(pemContent), c => c.charCodeAt(0));

const publicKey = await crypto.subtle.importKey(
    'spki',
    keyData,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
);

const encrypted = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    new TextEncoder().encode('data')
);
```

### Error Handling

```ts
import { importPublicKey, sha256 } from 'rsa-oaep-encryption';

try {
    const publicKey = importPublicKey(invalidPem);
    const encrypted = publicKey.encrypt('data', sha256.create());
} catch (error) {
    console.error('Encryption failed:', error.message);
    // Handle invalid PEM format, corrupted key, etc.
}
```

### Using ByteStringBuffer (Advanced)

For advanced binary manipulation:

```ts
import { ByteStringBuffer } from 'rsa-oaep-encryption';

const buffer = new ByteStringBuffer();
buffer.putBytes('Hello');
buffer.putByte(0x00);
buffer.putInt32(12345);

console.log(buffer.toHex());
console.log(buffer.length());

// Read data
const byte = buffer.getByte();
const bytes = buffer.getBytes(5);
```

## API Reference

### `importPublicKey(pem: string): RSAPublicKey`

Import a PEM-encoded RSA public key.

- **pem**: PEM format string (with or without headers)
- **Returns**: `RSAPublicKey` object with `encrypt` method

### `RSAPublicKey.encrypt(data: string, hash: HashAlgorithm): ArrayBuffer`

Encrypt data using RSA-OAEP.

- **data**: String to encrypt
- **hash**: Hash algorithm instance (e.g., `sha256.create()`)
- **Returns**: Encrypted data as `ArrayBuffer`

### Hash Creators

| Creator | Algorithm | Block Size |
|---------|-----------|------------|
| `sha1.create()` | SHA-1 | 64 bytes |
| `sha256.create()` | SHA-256 | 64 bytes |
| `sha384.create()` | SHA-384 | 128 bytes |
| `sha512.create()` | SHA-512 | 128 bytes |

### `HashAlgorithm` Interface

```ts
interface HashAlgorithm {
    blockLength: number;
    update(msg: string): HashAlgorithm;
    digest(): ByteStringBuffer;
}
```

## Documentation

Full API documentation is available at:

**[https://jiangjie.github.io/rsa-oaep-encryption/](https://jiangjie.github.io/rsa-oaep-encryption/)**

## Credits

This project is derived from [node-forge](https://github.com/digitalbazaar/forge) with the following modifications:

- Rewritten in TypeScript
- Removed Node.js-specific code
- Kept only RSA-OAEP encryption (removed PKCS1-v1_5, signatures, etc.)
- Limited hash algorithms to SHA-1/256/384/512 for Web Crypto API compatibility
- Changed return type to `ArrayBuffer` for Web Crypto API compatibility

## License

[BSD-3-Clause](LICENSE) - Compatible with the original node-forge license.

```
Copyright (c) 2010, Digital Bazaar, Inc.
Copyright (c) 2024-present, JiangJie
```
