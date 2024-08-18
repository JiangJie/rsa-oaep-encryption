[**rsa-oaep-encryption**](../README.md) • **Docs**

***

[rsa-oaep-encryption](../README.md) / importPublicKey

# Function: importPublicKey()

```ts
function importPublicKey(pem): {
  encrypt: ArrayBuffer;
}
```

Import a RSA public key from a PEM format string.
Used to encrypt data.

## Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `pem` | `string` | The PEM format string. |

## Returns

```ts
{
  encrypt: ArrayBuffer;
}
```

A function that can be used to encrypt data.

| Name | Type | Description | Defined in |
| ------ | ------ | ------ | ------ |
| `encrypt` | `ArrayBuffer` | Encrypt data using RSA key. | [mod.ts:27](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/mod.ts#L27) |

## Defined in

[mod.ts:17](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/mod.ts#L17)
