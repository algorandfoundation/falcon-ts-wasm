# falcon-1024-ts

TypeScript/WebAssembly bindings for deterministic [Falcon-1024](https://falcon-sign.info/) post-quantum signatures, backed by the [C implementation](https://github.com/algorand/falcon) of Falcon-1024 by [David Lazar](https://scholar.google.com/citations?user=Niwk8-QAAAAJ&hl=en) and [Chris Peikert](https://scholar.google.com/citations?user=PiZymREAAAAJ&hl=en). This is the same implementation used by the [go-algorand](https://github.com/algorand/go-algorand) Algorand client.

## Installation

```bash
# npm
npm install falcon-1024

# pnpm
pnpm add falcon-1024

# Bun
bun add falcon-1024
```

The package ships precompiled WebAssembly **embedded directly in the JavaScript** (there is no separate `.wasm` file to serve), with both ES module and CommonJS builds. It works out of the box in modern browsers, Node.js (ESM **and** CommonJS), Bun, and bundlers — no `fetch` shim or asset wiring required.

## Quick Start

```ts
import { falcon1024 } from "falcon-1024";

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
const { falcon1024 } = require("falcon-1024");
```

### Deterministic key generation from a seed

If you pass a seed, key generation is deterministic:

```ts
import { falcon1024 } from "falcon-1024";

const seed = crypto.getRandomValues(new Uint8Array(48));
const { publicKey, privateKey } = falcon1024.generateKey(seed);
```

The same 48-byte seed will always produce the same keypair.

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
  KeygenError,
  SigningError,
  VerificationError,
} from "falcon-1024";
import type { FalconApi } from "falcon-1024";
```

### `falcon1024`

An object implementing `FalconApi` with the following methods:

- `generateKey(seed?: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array }`\
  Generates a Falcon-1024 keypair.

  - If `seed` is provided, the keypair is derived deterministically from it.
  - If omitted, a 48-byte seed is created via `crypto.getRandomValues`.

- `signCompressed(privateKey: Uint8Array, message: Uint8Array): Uint8Array`\
  Creates a compressed Falcon-1024 signature of `message` using `privateKey`.

  - Throws `SigningError` if the key length is invalid or signing fails.

- `verifyCompressed(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean`\
  Verifies a compressed signature for `message` under `publicKey`.

  - Returns `true` if the signature is valid.
  - Throws `VerificationError` if the key/signature is malformed or verification fails.

### Constants

- `FALCON_DET1024_PUBKEY_SIZE: number`\
  Byte length of a Falcon-1024 public key.

- `FALCON_DET1024_PRIVKEY_SIZE: number`\
  Byte length of a Falcon-1024 private key.

- `FALCON_DET1024_SIG_COMPRESSED_MAXSIZE: number`\
  Maximum byte length of a compressed Falcon-1024 signature.

### Errors

All error classes extend `Error` and wrap underlying Falcon error codes:

- `KeygenError` – thrown by `generateKey` on key generation failures.
- `SigningError` – thrown by `signCompressed` on signing failures.
- `VerificationError` – thrown by `verifyCompressed` on verification failures.

## Environment & Requirements

- Dual ESM + CommonJS package. Both `import { generateKey } from "falcon-1024"`
  and `const { generateKey } = require("falcon-1024")` work with no extra setup.
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
