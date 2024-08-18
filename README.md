# RSA OAEP Encryption

[![NPM version](https://img.shields.io/npm/v/rsa-oaep-encryption.svg)](https://npmjs.org/package/rsa-oaep-encryption)
[![NPM downloads](https://badgen.net/npm/dm/rsa-oaep-encryption)](https://npmjs.org/package/rsa-oaep-encryption)
[![JSR Version](https://jsr.io/badges/@happy-js/rsa-oaep-encryption)](https://jsr.io/@happy-js/rsa-oaep-encryption)
[![JSR Score](https://jsr.io/badges/@happy-js/rsa-oaep-encryption/score)](https://jsr.io/@happy-js/rsa-oaep-encryption/score)
[![Build Status](https://github.com/jiangjie/rsa-oaep-encryption/actions/workflows/test.yml/badge.svg)](https://github.com/jiangjie/rsa-oaep-encryption/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/JiangJie/rsa-oaep-encryption/graph/badge.svg)](https://codecov.io/gh/JiangJie/rsa-oaep-encryption)

---

The purpose of this project is to provide a pure JavaScript implementation of `RSA` encryption in an environment that does not support the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

Thanks to [node-forge](https://github.com/digitalbazaar/forge), this project was forked from it and the following modifications and changes were made:
* Rewrite using `TypeScript`.
* Delete all `nodejs-only` codes.
* Only the `encryption` function using the `RSA-OAEP` algorithm is retained, and all other codes are deleted. It means that `PKCS1-v1_5` is not supported.
* The hash algorithm only supports `SHA1` `SHA-256` `SHA-384` `SHA-512` to be consistent with the `Web Crypto API`.
* The return value of the `encrypt` method is changed to `ArrayBuffer` to be consistent with the `Web Crypto API`.
* The code is almost `100%` covered and `tree-shake` friendly.

## Installation

```sh
# via pnpm
pnpm add rsa-oaep-encryption
# or via yarn
yarn add rsa-oaep-encryption
# or just from npm
npm install --save rsa-oaep-encryption
# via JSR
jsr add @happy-js/rsa-oaep-encryption
# for deno
deno add @happy-js/rsa-oaep-encryption
# for bun
bunx jsr add @happy-js/rsa-oaep-encryption
```

## Examples

```ts
import { importPublicKey, sha256 } from 'rsa-oaep-encryption';

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
xxxxx
-----END PUBLIC KEY-----`;
const encryptedData = importPublicKey(PUBLIC_KEY).encrypt('some data', sha256.create()); // or sha1 sha384 sha512
```

In an environment that supports the `Web Crypto API`, this is equivalent to the following code:
```ts
const keyData = base64ToBuffer(PUBLIC_KEY.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\s)/g, '')); // base64ToBuffer needs to be implemented
const publicKey = await crypto.subtle.importKey(
    'spki',
    keyData,
    {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
    },
    false,
    [
        'encrypt',
    ]
);
const encryptedData = await crypto.subtle.encrypt(
    {
        name: 'RSA-OAEP',
    },
    publicKey,
    new TextEncoder().encode('some data')
);
```

Of course, you can also use the exported `SHA` methods to perform SHA calculations separately in an environment that does not support the `Web Crypto API`.

Like this:
```ts
import { sha1 } from 'rsa-oaep-encryption';

const sha1Str = sha1.create().update('some data').digest().toHex();
```

## [Docs](docs/README.md)