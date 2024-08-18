[**rsa-oaep-encryption**](../README.md) • **Docs**

***

[rsa-oaep-encryption](../README.md) / ByteStringBuffer

# Class: ByteStringBuffer

Constructor for a binary string backed byte buffer.

## Param

the bytes to wrap (either encoded as string, one byte per
         character, or as an ArrayBuffer or Typed Array).

## Constructors

### new ByteStringBuffer()

```ts
new ByteStringBuffer(b?): ByteStringBuffer
```

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `b`? | `string` |

#### Returns

[`ByteStringBuffer`](ByteStringBuffer.md)

#### Defined in

[lib/ByteStringBuffer.ts:14](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/ByteStringBuffer.ts#L14)

## Properties

| Property | Type | Default value | Defined in |
| ------ | ------ | ------ | ------ |
| `read` | `number` | `0` | [lib/ByteStringBuffer.ts:12](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/ByteStringBuffer.ts#L12) |

## Methods

### bytes()

```ts
bytes(count?): string
```

Gets a binary encoded string of the bytes from this buffer without
modifying the read pointer.

#### Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `count`? | `number` | the number of bytes to get, omit to get all. |

#### Returns

`string`

a string full of binary encoded characters.

#### Defined in

[lib/ByteStringBuffer.ts:159](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/ByteStringBuffer.ts#L159)

***

### clear()

```ts
clear(): this
```

Clears this buffer.

#### Returns

`this`

this buffer.

#### Defined in

[lib/ByteStringBuffer.ts:183](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/ByteStringBuffer.ts#L183)

***

### compact()

```ts
compact(): this
```

Compacts this buffer.

#### Returns

`this`

this buffer.

#### Defined in

[lib/ByteStringBuffer.ts:170](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/ByteStringBuffer.ts#L170)

***

### getByte()

```ts
getByte(): number
```

Gets a byte from this buffer and advances the read pointer by 1.

#### Returns

`number`

the byte.

#### Defined in

[lib/ByteStringBuffer.ts:87](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/ByteStringBuffer.ts#L87)

***

### getBytes()

```ts
getBytes(count?): string
```

Reads bytes out as a binary encoded string and clears them from the
buffer. Note that the resulting string is binary encoded (in node.js this
encoding is referred to as `binary`, it is *not* `utf8`).

#### Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `count`? | `number` | the number of bytes to read, undefined or null for all. |

#### Returns

`string`

a binary encoded string of bytes.

#### Defined in

[lib/ByteStringBuffer.ts:134](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/ByteStringBuffer.ts#L134)

***

### getInt()

```ts
getInt(n): number
```

Gets an n-bit integer from this buffer in big-endian order and advances the
read pointer by ceil(n/8).

#### Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `n` | `8` \| `16` \| `24` \| `32` | the number of bits in the integer (8, 16, 24, or 32). |

#### Returns

`number`

the integer.

#### Defined in

[lib/ByteStringBuffer.ts:115](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/ByteStringBuffer.ts#L115)

***

### getInt32()

```ts
getInt32(): number
```

Gets a uint32 from this buffer in big-endian order and advances the read
pointer by 4.

#### Returns

`number`

the word.

#### Defined in

[lib/ByteStringBuffer.ts:97](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/ByteStringBuffer.ts#L97)

***

### length()

```ts
length(): number
```

Gets the number of bytes in this buffer.

#### Returns

`number`

the number of bytes in this buffer.

#### Defined in

[lib/ByteStringBuffer.ts:39](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/ByteStringBuffer.ts#L39)

***

### putByte()

```ts
putByte(b): this
```

Puts a byte in this buffer.

#### Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `b` | `number` | the byte to put. |

#### Returns

`this`

this buffer.

#### Defined in

[lib/ByteStringBuffer.ts:50](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/ByteStringBuffer.ts#L50)

***

### putBytes()

```ts
putBytes(bytes): this
```

Puts bytes in this buffer.

#### Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `bytes` | `string` | the bytes (as a binary encoded string) to put. |

#### Returns

`this`

this buffer.

#### Defined in

[lib/ByteStringBuffer.ts:61](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/ByteStringBuffer.ts#L61)

***

### putInt32()

```ts
putInt32(i): this
```

Puts a 32-bit integer in this buffer in big-endian order.

#### Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `i` | `number` | the 32-bit integer. |

#### Returns

`this`

this buffer.

#### Defined in

[lib/ByteStringBuffer.ts:74](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/ByteStringBuffer.ts#L74)

***

### toArrayBuffer()

```ts
toArrayBuffer(): ArrayBuffer
```

Converts this buffer to an ArrayBuffer.

#### Returns

`ArrayBuffer`

An ArrayBuffer.

#### Defined in

[lib/ByteStringBuffer.ts:211](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/ByteStringBuffer.ts#L211)

***

### toHex()

```ts
toHex(): string
```

Converts this buffer to a hexadecimal string.

#### Returns

`string`

a hexadecimal string.

#### Defined in

[lib/ByteStringBuffer.ts:194](https://github.com/JiangJie/rsa-oaep-encryption/blob/70be29a3b33e6f6c5e05bbfdb2dfaf9b5e77f09a/src/lib/ByteStringBuffer.ts#L194)
