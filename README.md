# @algorandfoundation/falcon-wasm

TypeScript/WebAssembly bindings for deterministic [Falcon-1024](https://falcon-sign.info/) post-quantum signatures, backed by the [C implementation](https://github.com/algorand/falcon) of Falcon-1024 by [David Lazar](https://scholar.google.com/citations?user=Niwk8-QAAAAJ&hl=en) and [Chris Peikert](https://scholar.google.com/citations?user=PiZymREAAAAJ&hl=en). This is the same implementation used by the [go-algorand](https://github.com/algorand/go-algorand) Algorand client.

## Installation

```bash
# npm
npm install @algorandfoundation/falcon-wasm

# pnpm
pnpm add @algorandfoundation/falcon-wasm

# Bun
bun add @algorandfoundation/falcon-wasm
```

The package ships precompiled WebAssembly **embedded directly in the JavaScript** (there is no separate `.wasm` file to serve), with both ES module and CommonJS builds. It works out of the box in modern browsers, Node.js (ESM **and** CommonJS), Bun, and bundlers — no `fetch` shim or asset wiring required.

## Quick Start

```ts
import { falcon1024 } from "@algorandfoundation/falcon-wasm";

const encoder = new TextEncoder();
const message = encoder.encode("hello, post-quantum world");

// 1. Generate a deterministic Falcon-1024 keypair
const { publicKey, privateKey } = falcon1024.generateKey(); // uses crypto.getRandomValues by default

// 2. Sign (compressed format)
const signature = falcon1024.signCompressed(privateKey, message);

// 3. Verify
const isValid = falcon1024.verifyCompressed(publicKey, signature, message);
console.log("Signature valid?", isValid); // true
```

The same API is available via CommonJS `require`:

```js
const { falcon1024 } = require("@algorandfoundation/falcon-wasm");
```

### Deterministic key generation from a seed

If you pass a seed, key generation is deterministic:

```ts
import { falcon1024 } from "@algorandfoundation/falcon-wasm";

const seed = crypto.getRandomValues(new Uint8Array(48));
const { publicKey, privateKey } = falcon1024.generateKey(seed);
```

The same 48-byte seed will always produce the same keypair.

### Randomized (salted) signatures

Alongside deterministic signing, the randomized Falcon-1024 mode from the Round 3 specification (the basis of the upcoming FN-DSA / FIPS 206 standard) is available. Keys are shared between both modes.

```ts
const signature = falcon1024.signCompressed(privateKey, message, true); // fresh 40-byte nonce
falcon1024.verifyCompressed(publicKey, signature, message); // mode detected from the header byte
```

> [!CAUTION]
> Randomized signing is **experimental** and implements the **NIST Round 3 Falcon submission only**. It is **not FN-DSA (FIPS 206)**.
>
> - **Not FN-DSA:** the standardised FN-DSA is expected to differ substantially from Round 3 (e.g. message hashing and domain separation, encodings and headers), so Round 3 randomized signatures will very likely **not** verify under FN-DSA. The output and API of this mode will change in a future release once FIPS 206 is final. Do not rely on it for long-lived signatures or interoperability.
> - **Not accepted on-chain:** Algorand on-chain verification (the AVM `falcon_verify` opcode) only accepts deterministic signatures. A randomized signature that passes `verifyCompressed` will still be rejected on-chain; check for `signature[0] === FALCON_DET1024_SIG_COMPRESSED_HEADER` if you need to mirror that behaviour.

## API

The signing operations are grouped under the `falcon1024` object, which
implements the `FalconApi` interface. (A sibling `falcon512` export implementing
the same interface will be added in the future.) Constants and error classes are
exported from the top-level module:

```ts
import {
  falcon1024,
  FALCON_DET1024_PUBKEY_SIZE,
  FALCON_DET1024_PRIVKEY_SIZE,
  FALCON_DET1024_SIG_COMPRESSED_MAXSIZE,
  FALCON_DET1024_SIG_COMPRESSED_HEADER,
  FALCON1024_SIG_COMPRESSED_MAXSIZE,
  FALCON1024_SIG_COMPRESSED_HEADER,
  KeygenError,
  SigningError,
  VerificationError,
} from "@algorandfoundation/falcon-wasm";
import type { FalconApi } from "@algorandfoundation/falcon-wasm";
```

### `falcon1024`

An object implementing `FalconApi` with the following methods:

- `generateKey(seed?: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array }`\
  Generates a Falcon-1024 keypair.

  - If `seed` is provided, the keypair is derived deterministically from it.
  - If omitted, a 48-byte seed is created via `crypto.getRandomValues`.

- `signCompressed(privateKey: Uint8Array, message: Uint8Array, randomized = false): Uint8Array`\
  Creates a compressed Falcon-1024 signature of `message` using `privateKey`.

  - By default the signature is deterministic.
  - With `randomized = true`, a randomized (salted) signature is created with a fresh nonce from `crypto.getRandomValues`; signing the same message twice yields different signatures.
  - Throws `SigningError` if the key length is invalid or signing fails.

- `verifyCompressed(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean`\
  Verifies a compressed signature (deterministic or randomized, detected from the header byte) for `message` under `publicKey`.

  - Returns `true` if the signature is valid.
  - Throws `VerificationError` if the key/signature is malformed, the header is unknown (`invalid format`), or verification fails.

### Constants

- `FALCON_DET1024_PUBKEY_SIZE: number`\
  Byte length of a Falcon-1024 public key.

- `FALCON_DET1024_PRIVKEY_SIZE: number`\
  Byte length of a Falcon-1024 private key.

- `FALCON_DET1024_SIG_COMPRESSED_MAXSIZE: number`\
  Maximum byte length of a deterministic compressed Falcon-1024 signature.

- `FALCON1024_SIG_COMPRESSED_MAXSIZE: number`\
  Maximum byte length of a randomized compressed Falcon-1024 signature.

- `FALCON_DET1024_SIG_COMPRESSED_HEADER: number`\
  Header byte of a deterministic compressed signature (`0xBA`).

- `FALCON1024_SIG_COMPRESSED_HEADER: number`\
  Header byte of a randomized compressed signature (`0x3A`).

### Errors

All error classes extend `Error` and wrap underlying Falcon error codes:

- `KeygenError` – thrown by `generateKey` on key generation failures.
- `SigningError` – thrown by `signCompressed` on signing failures.
- `VerificationError` – thrown by `verifyCompressed` on verification failures.

## Environment & Requirements

- Dual ESM + CommonJS package. Both `import { falcon1024 } from "@algorandfoundation/falcon-wasm"`
  and `const { falcon1024 } = require("@algorandfoundation/falcon-wasm")` work with no extra setup.
- The WebAssembly is embedded in the JavaScript, so there is no `.wasm` file to
  copy or serve — bundlers and runtimes load it with no asset wiring or `fetch`
  shim.
- Requires:
  - WebAssembly support.
  - A `crypto.getRandomValues` implementation (browser Web Crypto, Bun, or Nodes `crypto.webcrypto` wired to `globalThis.crypto`).

## Development

This repository uses pnpm for development.

### Prerequisites

- **Node.js >= 18** (with pnpm support)
- A POSIX shell environment (Linux/macOS). The build compiles the C code to WASM with emscripten, which is vendored as the `emsdk` git submodule. `pnpm run build` initializes the submodules and, on first run, installs and activates the pinned emscripten version locally.

### Building

Install dependencies:

```bash
pnpm install
```

Build the library (ESM + CommonJS bundles with embedded WASM, plus `.d.ts`):

```bash
pnpm run build
```

Run browser tests (Playwright):

```bash
pnpm run test:browser
```
