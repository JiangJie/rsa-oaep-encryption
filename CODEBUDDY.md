# CODEBUDDY.md

This file provides guidance to CodeBuddy Code when working with code in this repository.

## Project summary
- Pure TypeScript RSA-OAEP implementation forked from node-forge so that environments without Web Crypto API support can still import a PEM public key, encrypt data, and run SHA1/256/384/512 hashes with Web Crypto-compatible return types; only RSA-OAEP is retained and coverage is ~100% (`README.md:12-21`).
- The published entry points are `dist/main.cjs`, `dist/main.mjs`, and `dist/types.d.ts`, all bundled from `src/mod.ts` via Vite and driven by pnpm scripts (`package.json:8-30`).

## Tooling & prerequisites
- Use pnpm for all node-based workflows; every package script is defined with pnpm invocations, so install dependencies with pnpm before running them (`package.json:21-30`).
- Tests and coverage rely on Vitest with v8 coverage provider (`package.json:33-35`).
- TypeDoc generates HTML documentation, deployed via GitHub Pages (`package.json:36-37`).

## Common commands
| Purpose | Command | Notes |
| --- | --- | --- |
| Type check | `pnpm check` | Runs `tsc --noEmit` for the entire TypeScript surface. |
| Lint | `pnpm lint` | Executes ESLint across the repo. |
| Clean + verify | `pnpm prebuild` | Runs type-check and lint before bundling. |
| Build bundles/types | `pnpm build` | Uses Vite to emit CJS, ESM, and d.ts artifacts into `dist/`. |
| Full test suite + coverage | `pnpm test` | Runs Vitest with v8 coverage. |
| Watch mode tests | `pnpm test:watch` | Runs Vitest in watch mode. |
| Test UI | `pnpm test:ui` | Opens Vitest UI for interactive testing. |
| Generate docs | `pnpm docs` | Cleans `docs/` and runs TypeDoc to generate HTML documentation. |
| Run a single test file | `pnpm exec vitest run tests/rsa.test.ts` | Can swap in `tests/sha.test.ts` or `tests/coverage.test.ts`. |

## Architecture overview
### Public API surface
- `src/mod.ts` re-exports the hash creators (`sha1`, `sha256`, `sha384`, `sha512`) and exposes the `RSAPublicKey` interface alongside `importPublicKey`, which wraps the lower-level RSA module into a Web Crypto-style API returning `ArrayBuffer` (`src/mod.ts:1-64`).
- `src/lib/defines.ts` specifies the `HashAlgorithm` contract consumed by RSA-OAEP encoding and the `HashAlgorithmCreator` factories used throughout the hashing modules (`src/lib/defines.ts:1-55`).

### RSA/OAEP pipeline
- `src/lib/rsa.ts` handles ASN.1 decoding of `SubjectPublicKeyInfo`, PEM parsing, jsbn big-integer math, and OAEP padding; `publicKeyFromPem` parses the PEM, `publicKeyFromAsn1` validates OIDs, and `setRsaPublicKey().encrypt` feeds data through `encode_rsa_oaep` before raw RSA exponentiation (`src/lib/rsa.ts:69-222`).
- ASN.1, PEM, PKCS#1, PRNG, AES, and buffer helpers live under `src/lib/` and are the only dependencies required at runtime, preserving the "pure JS" guarantee noted in the README (`README.md:12-21`).

### Hash primitives and utilities
- The hash creators exported by `src/mod.ts` come from `src/lib/sha1.ts`, `src/lib/sha256.ts`, and `src/lib/sha512.ts`, each producing objects that satisfy the `HashAlgorithm` interface for OAEP usage and standalone digest operations (`src/mod.ts:4-8`, `src/lib/defines.ts:1-55`).
- `ByteStringBuffer` underpins binary manipulation (used heavily by RSA parsing) and is re-exported for advanced callers who need to interop with the lower-level APIs (`src/mod.ts:4`, `src/lib/ByteStringBuffer.ts`).

### Testing strategy
- `tests/rsa.test.ts` asserts that invalid PEMs throw, then encrypts/decrypts test strings against the Web Crypto API across all supported hashes for 100 iterations to ensure deterministic interoperability (`tests/rsa.test.ts:47-138`).
- `tests/sha.test.ts` compares each hash implementation's `ArrayBuffer` output against `crypto.subtle.digest` to guarantee byte-for-byte parity with Web Crypto (`tests/sha.test.ts:6-36`).
- `tests/coverage.test.ts` provides additional edge case tests to achieve ~100% code coverage (`tests/coverage.test.ts`).

### Tooling outputs & docs
- Build artifacts (`dist/main.cjs`, `dist/main.mjs`, `dist/types.d.ts`) are the only files published alongside the source set defined under `files` in `package.json`, so remember to run `pnpm build` before publishing (`package.json:8-31`).
- TypeDoc generates HTML documentation, deployed to GitHub Pages at https://jiangjie.github.io/rsa-oaep-encryption/ (`package.json:36-37`, `README.md:271-275`).
