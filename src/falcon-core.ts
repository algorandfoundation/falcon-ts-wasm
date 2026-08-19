// Shared, glue-agnostic Falcon-1024 implementation.
//
// The only thing that differs between the ESM and CommonJS builds is *how* the
// Emscripten module is instantiated:
//   - ESM (`index.ts`) awaits the async glue (browser-main-thread safe; large
//     WASM modules cannot be compiled synchronously on a browser main thread).
//   - CJS (`index.cjs.ts`) uses the synchronous glue, because CommonJS cannot
//     contain top-level `await`. CJS only runs under Node, which has no
//     synchronous-compilation size limit.
// Both feed the resulting module object into `makeApi` below.

type FalconModule = any;

// Constants from deterministic.h and falcon.h
const FALCON_DET1024_LOGN = 10;

function falconPrivKeySize(logn: number): number {
  if (logn <= 3) {
    return (3 << logn) + 1;
  }
  return ((10 - (logn >> 1)) << (logn - 2)) + (1 << logn) + 1;
}

function falconPubKeySize(logn: number): number {
  if (logn <= 1) {
    return 4 + 1;
  }
  return (7 << (logn - 2)) + 1;
}

function falconSigCompressedMaxSize(logn: number): number {
  const value = (11 << logn) + (101 >> (10 - logn));
  return ((value + 7) >> 3) + 41;
}

export const FALCON_DET1024_PUBKEY_SIZE = falconPubKeySize(FALCON_DET1024_LOGN);
export const FALCON_DET1024_PRIVKEY_SIZE =
  falconPrivKeySize(FALCON_DET1024_LOGN);
export const FALCON_DET1024_SIG_COMPRESSED_MAXSIZE =
  falconSigCompressedMaxSize(FALCON_DET1024_LOGN) - 40 + 1;

const SHAKE256_CONTEXT_SIZE = 26 * 8;

class FalconError extends Error {
  constructor(context: number | string) {
    if (typeof context === "string") {
      super(context);
      return;
    }

    if (context === -1) {
      super("OS random number generator failure");
    } else if (context === -2) {
      super("buffer too small");
    } else if (context === -3) {
      super("invalid format");
    } else if (context === -4) {
      super("bad signature");
    } else if (context === -5) {
      super("bad argument");
    } else if (context === -6) {
      super("internal error");
    } else {
      super(`unknown error code ${context}`);
    }
  }
}

export class KeygenError extends FalconError {
  constructor(context: number | string) {
    super(context);
    this.name = "KeygenError";
  }
}

export class SigningError extends FalconError {
  constructor(context: number | string) {
    super(context);
    this.name = "SigningError";
  }
}

export class VerificationError extends FalconError {
  constructor(context: number | string) {
    super(context);
    this.name = "VerificationError";
  }
}

export interface FalconApi {
  generateKey(seed?: Uint8Array): {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  };
  signCompressed(privateKey: Uint8Array, message: Uint8Array): Uint8Array;
  verifyCompressed(
    publicKey: Uint8Array,
    signature: Uint8Array,
    message: Uint8Array,
  ): boolean;
}

/**
 * Builds the public API bound to an instantiated Emscripten module. The module
 * is created by the entry point (ESM or CJS) and injected here so this file
 * stays independent of how/when the WASM was compiled.
 */
export function makeApi(module: FalconModule): FalconApi {
  class WasmPtr {
    address: number;
    name: string;
    allocationSize: number;

    protected constructor(name: string, allocationSize: number) {
      this.address = 0;
      this.name = name;
      this.allocationSize = allocationSize;
    }

    static u32(name: string, allocationSize: number) {
      return new Uint32WasmPtr(name, allocationSize);
    }

    static u8(name: string, allocationSize: number) {
      return new Uint8WasmPtr(name, allocationSize);
    }
  }

  class Uint32WasmPtr extends WasmPtr {
    read(): number {
      return module.HEAPU32[this.address >> 2];
    }
  }

  class Uint8WasmPtr extends WasmPtr {
    read(length?: number): Uint8Array {
      if (length != undefined && length > this.allocationSize) {
        throw Error(
          `Tried to read length (${length}) which exceeds allocation size (${this.allocationSize})`,
        );
      }

      return new Uint8Array(
        module.HEAPU8.buffer,
        this.address,
        length ?? this.allocationSize,
      ).slice();
    }

    write(value: Uint8Array) {
      if (value.length != this.allocationSize) {
        throw Error(
          `Cannot write value to ${this.name} pointer. Expected length of ${this.allocationSize}, got ${value.length}`,
        );
      }

      module.HEAPU8.set(value, this.address);
    }
  }

  /** Given the list of WasmPtr, allocates memory for each, runs the function, and frees the memory. This should be the ONLY function that _malloc and _free are called */
  function withWasmAllocations<T>(variables: WasmPtr[], fn: () => T): T {
    try {
      for (const v of variables.filter((v) => v.allocationSize > 0)) {
        try {
          v.address = module._malloc(v.allocationSize);
        } catch (e) {
          throw new FalconError(`Failed to allocate memory for ${v.name}`);
        }
      }

      return fn();
    } finally {
      for (const v of variables) {
        if (v.address !== undefined && v.address !== 0) {
          try {
            module._free(v.address);
          } catch (e) {
            console.error(
              `Failed to free memory for ${v.name} (${v.address}):`,
              e,
            );
          }
        }
      }
    }
  }

  /**
   * Generates a Falcon public/private key pair from the given seed.
   * @param seed - Optional seed bytes. If not provided, a random 48-byte seed will be generated.
   * @returns An object containing the publicKey and privateKey as Uint8Arrays.
   */
  function generateKey(seed?: Uint8Array): {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  } {
    if (!seed || seed.length === 0) {
      seed = new Uint8Array(48);
      crypto.getRandomValues(seed);
    }
    const seedLen = seed.length;

    const rngPtr = WasmPtr.u8("rng", SHAKE256_CONTEXT_SIZE);
    const seedPtr = WasmPtr.u8("seed", seedLen);
    const privateKeyPtr = WasmPtr.u8("privateKey", FALCON_DET1024_PRIVKEY_SIZE);
    const publicKeyPtr = WasmPtr.u8("publicKey", FALCON_DET1024_PUBKEY_SIZE);

    return withWasmAllocations(
      [rngPtr, seedPtr, privateKeyPtr, publicKeyPtr],
      () => {
        seedPtr.write(seed);
        module._shake256_init_prng_from_seed(
          rngPtr.address,
          seedPtr.address,
          seedLen,
        );

        const result = module._falcon_det1024_keygen(
          rngPtr.address,
          privateKeyPtr.address,
          publicKeyPtr.address,
        );

        const publicKey = publicKeyPtr.read();
        const privateKey = privateKeyPtr.read();

        if (result !== 0) {
          throw new KeygenError(result);
        }

        return { publicKey, privateKey };
      },
    );
  }

  /**
   * Signs a message with the given private key using compressed format.
   * @param privateKey - The private key (FALCON_DET1024_PRIVKEY_SIZE bytes).
   * @param message - The message to sign.
   * @returns The compressed signature as a Uint8Array.
   */
  function signCompressed(
    privateKey: Uint8Array,
    message: Uint8Array,
  ): Uint8Array {
    if (privateKey.length !== FALCON_DET1024_PRIVKEY_SIZE) {
      throw new SigningError(
        `Invalid private key length: ${privateKey.length}. Expected ${FALCON_DET1024_PRIVKEY_SIZE}.`,
      );
    }

    const msgLen = message.length;

    const sigPtr = WasmPtr.u8("sig", FALCON_DET1024_SIG_COMPRESSED_MAXSIZE);
    const sigLenPtr = WasmPtr.u32("sigLen", 4); // size_t pointer
    const privateKeyPtr = WasmPtr.u8("privateKey", FALCON_DET1024_PRIVKEY_SIZE);
    const msgPtr = WasmPtr.u8("msg", msgLen);

    const allocations = [sigPtr, sigLenPtr, privateKeyPtr, msgPtr];

    return withWasmAllocations(allocations, () => {
      privateKeyPtr.write(privateKey);

      if (msgLen > 0) {
        msgPtr.write(message);
      }

      const result = module._falcon_det1024_sign_compressed(
        sigPtr.address,
        sigLenPtr.address,
        privateKeyPtr.address,
        msgPtr.address,
        msgLen,
      );

      const signature = sigPtr.read(sigLenPtr.read());

      if (result !== 0) {
        throw new SigningError(result);
      }

      return signature;
    });
  }

  /**
   * Verifies a compressed signature against a message and public key.
   * @param publicKey - The public key (FALCON_DET1024_PUBKEY_SIZE bytes).
   * @param signature - The compressed signature.
   * @param message - The original message.
   * @returns true if the signature is valid.
   * @throws VerificationError if verification fails.
   */
  function verifyCompressed(
    publicKey: Uint8Array,
    signature: Uint8Array,
    message: Uint8Array,
  ): boolean {
    if (publicKey.length !== FALCON_DET1024_PUBKEY_SIZE) {
      throw new VerificationError(
        `Invalid public key length: ${publicKey.length}. Expected ${FALCON_DET1024_PUBKEY_SIZE}.`,
      );
    }

    if (signature.length === 0) {
      throw new VerificationError("Empty signature");
    }

    if (signature.length > FALCON_DET1024_SIG_COMPRESSED_MAXSIZE) {
      throw new VerificationError(
        `Invalid signature length: ${signature.length}. Maximum is ${FALCON_DET1024_SIG_COMPRESSED_MAXSIZE}.`,
      );
    }

    const msgLen = message.length;

    const sigPtr = WasmPtr.u8("sig", signature.length);
    const publicKeyPtr = WasmPtr.u8("publicKey", FALCON_DET1024_PUBKEY_SIZE);
    const msgPtr = WasmPtr.u8("msg", msgLen);

    const allocations = [sigPtr, publicKeyPtr, msgPtr];

    return withWasmAllocations(allocations, () => {
      sigPtr.write(signature);
      publicKeyPtr.write(publicKey);

      if (msgLen > 0) {
        msgPtr.write(message);
      }

      const result = module._falcon_det1024_verify_compressed(
        sigPtr.address,
        signature.length,
        publicKeyPtr.address,
        msgPtr.address,
        msgLen,
      );

      if (result !== 0) {
        throw new VerificationError(result);
      }

      return true;
    });
  }

  return { generateKey, signCompressed, verifyCompressed };
}
