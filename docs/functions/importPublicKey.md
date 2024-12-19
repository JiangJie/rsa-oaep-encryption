[**rsa-oaep-encryption**](../README.md)

***

[rsa-oaep-encryption](../README.md) / importPublicKey

# Function: importPublicKey()

```ts
function importPublicKey(pem): RSAPublicKey
```

Import a RSA public key from a PEM format string.
Used to encrypt data.

## Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `pem` | `string` | The PEM format string. |

## Returns

[`RSAPublicKey`](../interfaces/RSAPublicKey.md)

A function that can be used to encrypt data.

## Defined in

[mod.ts:30](https://github.com/JiangJie/rsa-oaep-encryption/blob/11c92d65840bc30800ad745b80b41f78d60b8626/src/mod.ts#L30)
