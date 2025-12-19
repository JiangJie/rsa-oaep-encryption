# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-12-20

### Changed

- **BREAKING**: Change license from GPL-3.0 to BSD-3-Clause for compliance with node-forge upstream
- Migrate test framework from Deno to Vitest
- Replace Rollup with Vite for bundling
- Switch TypeDoc output from Markdown to HTML format

### Added

- Add `@stylistic/eslint-plugin` for consistent code formatting
- Add `tests/coverage.test.ts` for improved branch coverage
- Add navigation links to GitHub, npm, and JSR in documentation
- Add comprehensive JSDoc documentation with `@example` for public API
- Add `@example` to `sha1`, `sha256`, `sha384`, `sha512` hash creators
- Add `toArrayBuffer()` tests for `ByteStringBuffer` when read pointer > 0

### Removed

- Remove `deno.json` as Deno is no longer used for testing
- Remove generated docs from version control (now deployed via CI)
- Remove dead code in `asn1.ts`, `prng.ts`, and `jsbn.ts`

### Fixed

- Fix `ByteStringBuffer.toArrayBuffer()` offset calculation when read pointer > 0
- Fix code style issues across multiple source files

### CI/CD

- Refactor GitHub Actions workflows
- Add docs deployment workflow
- Improve publish workflows with pnpm support
- Upgrade GitHub Actions to latest versions

### Chores

- Upgrade dev dependencies
- Update ESLint config to use `defineConfig` API
- Add `CODEBUDDY.md` project documentation
- Remove `.npmrc` file
- Remove underscore prefix from private members in `ByteStringBuffer`

## [1.0.1] - 2024-12-19

### Added

- Export `HashAlgorithm.blockLength` property
- Export `ByteStringBuffer.at` method

### Changed

- Update dependencies
- Update documentation

## [1.0.0] - 2024-08-18

### Added

- Initial release
- Pure JavaScript implementation of RSA-OAEP encryption
- Support for SHA-1, SHA-256, SHA-384, SHA-512 hash algorithms
- `importPublicKey` function to import PEM-encoded public keys
- `sha1`, `sha256`, `sha384`, `sha512` hash creators
- `ByteStringBuffer` utility class for binary manipulation
- Full compatibility with Web Crypto API output formats
- GitHub Actions CI/CD workflows
- TypeDoc-generated API documentation

[1.1.0]: https://github.com/JiangJie/rsa-oaep-encryption/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/JiangJie/rsa-oaep-encryption/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/JiangJie/rsa-oaep-encryption/releases/tag/v1.0.0
