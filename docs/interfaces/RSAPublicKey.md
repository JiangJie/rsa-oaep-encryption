[**rsa-oaep-encryption**](../README.md) • **Docs**

***

[rsa-oaep-encryption](../README.md) / RSAPublicKey

# Interface: RSAPublicKey

RSA public key.

## Methods

### encrypt()

```ts
encrypt(data, hash): ArrayBuffer
```

Encrypt data using RSA key.

#### Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `data` | `string` | A string to be encrypted. |
| `hash` | [`HashAlgorithm`](HashAlgorithm.md) | Which hash algorithm to use. |

#### Returns

`ArrayBuffer`

Encrypted data as ArrayBuffer.

#### Defined in

[mod.ts:20](https://github.com/JiangJie/rsa-oaep-encryption/blob/dfe951b5281117ed87c26600202442b83c94c043/src/mod.ts#L20)
