[**rsa-oaep-encryption**](../README.md) • **Docs**

***

[rsa-oaep-encryption](../README.md) / HashAlgorithm

# Interface: HashAlgorithm

A hash algorithm.

## Properties

| Property | Type | Defined in |
| ------ | ------ | ------ |
| `algorithm` | `string` | [lib/defines.ts:7](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/defines.ts#L7) |
| `digestLength` | `number` | [lib/defines.ts:8](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/defines.ts#L8) |
| `messageLength` | `number` | [lib/defines.ts:9](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/defines.ts#L9) |

## Methods

### digest()

```ts
digest(): ByteStringBuffer
```

#### Returns

[`ByteStringBuffer`](../classes/ByteStringBuffer.md)

#### Defined in

[lib/defines.ts:12](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/defines.ts#L12)

***

### start()

```ts
start(): this
```

#### Returns

`this`

#### Defined in

[lib/defines.ts:10](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/defines.ts#L10)

***

### update()

```ts
update(msg): this
```

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `msg` | `string` |

#### Returns

`this`

#### Defined in

[lib/defines.ts:11](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/defines.ts#L11)
