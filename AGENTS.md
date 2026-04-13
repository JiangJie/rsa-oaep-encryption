# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Project summary
- Pure TypeScript RSA-OAEP implementation forked from node-forge so that environments without Web Crypto API support can still import a PEM public key, encrypt data, and run SHA1/256/384/512 hashes with Web Crypto-compatible return types; only RSA-OAEP is retained and coverage is 100%.
- Zero runtime dependencies — all cryptographic primitives are self-contained under `src/lib/`.
- The published entry points are `dist/main.cjs`, `dist/main.mjs`, and `dist/types.d.ts`, all bundled from `src/mod.ts` via Vite. The package declares `"sideEffects": false` for tree-shaking.

## Tooling & prerequisites
- Use **pnpm** for all workflows.
- Tests and coverage rely on **Vitest** with v8 coverage provider.
- TypeDoc generates HTML documentation, deployed via GitHub Pages.
- **TypeScript must stay on 5.x** — vite-plugin-dts emits empty d.ts files under TypeScript 6.x.

## Common commands
| Purpose | Command | Notes |
| --- | --- | --- |
| Type check | `pnpm check` | Runs `tsc --noEmit`. |
| Lint | `pnpm lint` | ESLint across the repo. |
| Clean + verify | `pnpm prebuild` | Type-check then lint before bundling. |
| Build bundles/types | `pnpm build` | Vite emits CJS, ESM, and d.ts into `dist/`. |
| Full test suite + coverage | `pnpm test` | Vitest with v8 coverage — **must stay at 100%**. |
| Watch mode tests | `pnpm test:watch` | Vitest in watch mode. |
| Test UI | `pnpm test:ui` | Vitest UI for interactive testing. |
| Generate docs | `pnpm docs` | Cleans `docs/` and runs TypeDoc. |
| Run a single test file | `pnpm exec vitest run tests/rsa.test.ts` | Swap in `tests/sha.test.ts` or `tests/coverage.test.ts`. |

## Architecture overview

### Public API surface (`src/mod.ts`)
- Re-exports hash creators (`sha1`, `sha256`, `sha384`, `sha512`), the `ByteStringBuffer` class, and type exports (`HashAlgorithm`, `HashAlgorithmCreator`).
- Exposes `importPublicKey(pem) → RSAPublicKey` which wraps the lower-level RSA module into a Web Crypto-style API returning `ArrayBuffer`.

### Encryption pipeline (call chain)
```
importPublicKey(pem)
  → publicKeyFromPem (src/lib/rsa.ts)
    → pemDecode (src/lib/pem.ts)          — PEM → DER binary string
    → fromDer (src/lib/asn1.ts)           — DER → ASN.1 tree
    → publicKeyFromAsn1                    — ASN.1 → IBigInteger(n, e)
  → RSAPublicKey.encrypt(data, hash)
    → encode_rsa_oaep (src/lib/pkcs1.ts)  — OAEP padding with MGF1
      → random.generateSync (src/lib/random.ts) — PRNG seed via AES-CTR (src/lib/aes.ts)
    → rsaEncrypt                           — IBigInteger.modPow then → ArrayBuffer
```

### Internal modules (`src/lib/`)
| File | Role |
| --- | --- |
| `rsa.ts` | PEM parsing, ASN.1 OID validation, RSA exponentiation via `IBigInteger.modPow` |
| `bigint.ts` | `IBigInteger` interface + `NativeBigInteger` (native BigInt) + `createBigInteger` factory with runtime detection |
| `pkcs1.ts` | OAEP encode + MGF1 mask generation |
| `asn1.ts` | DER parser, `SubjectPublicKeyInfo` / `RSAPublicKey` validators |
| `pem.ts` | PEM envelope decode (regex + base64) |
| `jsbn.ts` | Fallback big-integer arithmetic: `BigInteger` class + Montgomery reduction for `modPow` |
| `ByteStringBuffer.ts` | Binary string-backed byte buffer used throughout for I/O |
| `sha1.ts` / `sha256.ts` / `sha512.ts` | Hash implementations satisfying `HashAlgorithm` interface |
| `random.ts` | Fortuna-based PRNG using AES-128 CTR from `aes.ts` |
| `prng.ts` | PRNG context with entropy pool management |
| `aes.ts` | AES-128 block cipher (key expansion + single-block encrypt) for PRNG |
| `util.ts` | `xorBytes` and `decode64` helpers |
| `defines.ts` | `HashAlgorithm` and `HashAlgorithmCreator` interface definitions |

### Tree-shaking conventions
- `package.json` declares `"sideEffects": false`.
- Module top-level function calls and `new` expressions must be annotated with `/*#__PURE__*/` to help bundlers eliminate unused code (see `src/lib/random.ts`, `src/lib/jsbn.ts`).
- Vite build uses `treeshake: { moduleSideEffects: false, propertyReadSideEffects: false }`.

### Testing strategy
- `tests/rsa.test.ts` — Encrypts test strings with this library, decrypts with Web Crypto API across all 4 hash algorithms for 100 iterations to verify interoperability.
- `tests/sha.test.ts` — Compares each hash implementation's output byte-for-byte against `crypto.subtle.digest`.
- `tests/coverage.test.ts` — Edge case tests for internal modules (`ByteStringBuffer`, `BigInteger`, `ASN.1`, `PEM`) to maintain 100% branch coverage.
- **Coverage must remain at 100%** for statements, functions, and lines. Branch coverage should also be 100%.
