[**rsa-oaep-encryption**](../README.md)

***

[rsa-oaep-encryption](../README.md) / HashAlgorithm

# Interface: HashAlgorithm

A hash algorithm.

## Properties

| Property | Type | Defined in |
| ------ | ------ | ------ |
| `algorithm` | `string` | [lib/defines.ts:7](https://github.com/JiangJie/rsa-oaep-encryption/blob/11c92d65840bc30800ad745b80b41f78d60b8626/src/lib/defines.ts#L7) |
| `blockLength` | `number` | [lib/defines.ts:8](https://github.com/JiangJie/rsa-oaep-encryption/blob/11c92d65840bc30800ad745b80b41f78d60b8626/src/lib/defines.ts#L8) |
| `digestLength` | `number` | [lib/defines.ts:9](https://github.com/JiangJie/rsa-oaep-encryption/blob/11c92d65840bc30800ad745b80b41f78d60b8626/src/lib/defines.ts#L9) |
| `messageLength` | `number` | [lib/defines.ts:10](https://github.com/JiangJie/rsa-oaep-encryption/blob/11c92d65840bc30800ad745b80b41f78d60b8626/src/lib/defines.ts#L10) |

## Methods

### digest()

```ts
digest(): ByteStringBuffer
```

#### Returns

[`ByteStringBuffer`](../classes/ByteStringBuffer.md)

#### Defined in

[lib/defines.ts:13](https://github.com/JiangJie/rsa-oaep-encryption/blob/11c92d65840bc30800ad745b80b41f78d60b8626/src/lib/defines.ts#L13)

***

### start()

```ts
start(): this
```

#### Returns

`this`

#### Defined in

[lib/defines.ts:11](https://github.com/JiangJie/rsa-oaep-encryption/blob/11c92d65840bc30800ad745b80b41f78d60b8626/src/lib/defines.ts#L11)

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

[lib/defines.ts:12](https://github.com/JiangJie/rsa-oaep-encryption/blob/11c92d65840bc30800ad745b80b41f78d60b8626/src/lib/defines.ts#L12)
