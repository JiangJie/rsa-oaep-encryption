# CODEBUDDY.md

This file provides guidance to CodeBuddy Code when working with code in this repository.

## Project summary
- Pure TypeScript RSA-OAEP implementation forked from node-forge so that environments without Web Crypto API support can still import a PEM public key, encrypt data, and run SHA1/256/384/512 hashes with Web Crypto-compatible return types; only RSA-OAEP is retained and coverage is ~100% (`README.md:12-21`).
- The published entry points are `dist/main.cjs`, `dist/main.mjs`, and `dist/types.d.ts`, all bundled from `src/mod.ts` via Rollup and driven by pnpm scripts (`package.json:8-30`).

## Tooling & prerequisites
- Use pnpm for all node-based workflows; every package script is defined with pnpm invocations, so install dependencies with pnpm before running them (`package.json:21-30`).
- Tests and coverage rely on Deno plus the local import map that aliases `rsa-oaep-encryption` to `./src/mod.ts`; run Deno commands from the repo root so the `deno.json` import map is picked up (`package.json:26-27`, `deno.json:1-7`).
- TypeDoc generates Markdown documentation into `docs/`, and README links directly to that output, so regenerate docs whenever the exported surface changes (`package.json:28-29`, `README.md:83`).

## Common commands
| Purpose | Command | Notes |
| --- | --- | --- |
| Type check | `pnpm check` | Runs `tsc --noEmit` for the entire TypeScript surface (`package.json:21-23`). |
| Lint | `pnpm lint` | Executes ESLint across the repo (`package.json:23-24`). |
| Clean + verify | `pnpm prebuild` | Removes `dist/`, then runs type-check and lint before bundling (`package.json:24-25`). |
| Build bundles/types | `pnpm build` | Uses Rollup config to emit CJS, ESM, and d.ts artifacts into `dist/` (`package.json:24-26`). |
| Full test suite + LCOV | `pnpm test` | Runs `deno test --coverage --clean`, then generates LCOV data under `coverage/` (`package.json:26-27`). |
| HTML coverage report | `pnpm test:html` | Same Deno test run but renders an HTML report (`package.json:27-28`). |
| Generate docs | `pnpm docs` | Cleans `docs/` and runs TypeDoc via the markdown plugin (`package.json:28-29`). |
| Run a single test file | `deno test tests/rsa.test.ts` | Uses the import map in `deno.json`, so you can swap in `tests/sha.test.ts` for hashing-only checks (`deno.json:1-7`, `tests/rsa.test.ts:47-116`). |

## Architecture overview
### Public API surface
- `src/mod.ts` re-exports the hash creators (`sha1`, `sha256`, `sha384`, `sha512`) and exposes the `RSAPublicKey` interface alongside `importPublicKey`, which wraps the lower-level RSA module into a Web Crypto-style API returning `ArrayBuffer` (`src/mod.ts:1-39`).
- `src/lib/defines.ts` specifies the `HashAlgorithm` contract consumed by RSA-OAEP encoding and the `HashAlgorithmCreator` factories used throughout the hashing modules (`src/lib/defines.ts:3-21`).

### RSA/OAEP pipeline
- `src/lib/rsa.ts` handles ASN.1 decoding of `SubjectPublicKeyInfo`, PEM parsing, jsbn big-integer math, and OAEP padding; `publicKeyFromPem` parses the PEM, `publicKeyFromAsn1` validates OIDs, and `setRsaPublicKey().encrypt` feeds data through `encode_rsa_oaep` before raw RSA exponentiation (`src/lib/rsa.ts:69-222`).
- ASN.1, PEM, PKCS#1, PRNG, AES, and buffer helpers live under `src/lib/` and are the only dependencies required at runtime, preserving the "pure JS" guarantee noted in the README (`README.md:12-21`).

### Hash primitives and utilities
- The hash creators exported by `src/mod.ts` come from `src/lib/sha1.ts`, `src/lib/sha256.ts`, and `src/lib/sha512.ts`, each producing objects that satisfy the `HashAlgorithm` interface for OAEP usage and standalone digest operations (`src/mod.ts:4-8`, `src/lib/defines.ts:3-21`).
- `ByteStringBuffer` underpins binary manipulation (used heavily by RSA parsing) and is re-exported for advanced callers who need to interop with the lower-level APIs (`src/mod.ts:4`, `src/lib/rsa.ts:103-140`).

### Testing strategy
- `tests/rsa.test.ts` imports the library via the Deno import map, asserts that invalid PEMs throw, then encrypts/decrypts test strings against the Web Crypto API across all supported hashes for 100 iterations to ensure deterministic interoperability (`tests/rsa.test.ts:47-116`).
- `tests/sha.test.ts` compares each hash implementation's `ArrayBuffer` output against `crypto.subtle.digest` to guarantee byte-for-byte parity with Web Crypto (`tests/sha.test.ts:6-16`).

### Tooling outputs & docs
- Build artifacts (`dist/main.cjs`, `dist/main.mjs`, `dist/types.d.ts`) are the only files published alongside the source set defined under `files` in `package.json`, so remember to run `pnpm build` before publishing (`package.json:8-31`).
- TypeDoc plus the markdown plugin renders API docs beneath `docs/`, and the root README links to `docs/README.md`, so keep that folder up to date when signatures change (`package.json:28-29`, `README.md:83`).
