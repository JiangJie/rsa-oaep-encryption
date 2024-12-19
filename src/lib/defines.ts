import type { ByteStringBuffer } from './ByteStringBuffer.ts';

/**
 * A hash algorithm.
 */
export interface HashAlgorithm {
    algorithm: string;
    blockLength: number;
    digestLength: number;
    messageLength: number;
    start(): this;
    update(msg: string): this;
    digest(): ByteStringBuffer;
}

/**
 * A hash algorithm creator.
 */
export interface HashAlgorithmCreator {
    create(): HashAlgorithm;
}
