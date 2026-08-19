// ESM entry point.
//
// Uses the asynchronous Emscripten glue and a top-level `await`. Async WASM
// compilation works on a browser main thread regardless of module size, so this
// build is safe for browsers as well as Node ESM. The WASM is embedded in the
// glue (SINGLE_FILE), so nothing is fetched at runtime.
import createModule from "./falcon_wasm.js";
import { makeApi } from "./falcon-core";

const module = await createModule();

/**
 * Falcon-1024 signature API. Grouping the operations under a named object leaves
 * room for a sibling `falcon512` export once Falcon-512 support is added.
 */
export const falcon1024 = makeApi(module);

export {
  FALCON_DET1024_PUBKEY_SIZE,
  FALCON_DET1024_PRIVKEY_SIZE,
  FALCON_DET1024_SIG_COMPRESSED_MAXSIZE,
  KeygenError,
  SigningError,
  VerificationError,
} from "./falcon-core";
export type { FalconApi } from "./falcon-core";
