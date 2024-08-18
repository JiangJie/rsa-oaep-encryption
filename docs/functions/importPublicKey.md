[**rsa-oaep-encryption**](../README.md) • **Docs**

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

[mod.ts:30](https://github.com/JiangJie/rsa-oaep-encryption/blob/dfe951b5281117ed87c26600202442b83c94c043/src/mod.ts#L30)
