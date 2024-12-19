[**rsa-oaep-encryption**](../README.md)

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

[mod.ts:20](https://github.com/JiangJie/rsa-oaep-encryption/blob/11c92d65840bc30800ad745b80b41f78d60b8626/src/mod.ts#L20)
