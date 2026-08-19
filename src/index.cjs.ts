// CommonJS entry point.
//
// CommonJS cannot contain top-level `await`, so this build uses the synchronous
// Emscripten glue (`WASM_ASYNC_COMPILATION=0`, with the factory's `async`
// keyword stripped by the build). CJS only runs under Node, which — unlike a
// browser main thread — places no size limit on synchronous WASM compilation.
// The WASM is embedded in the glue (SINGLE_FILE), so nothing is fetched.
import createModule from "./falcon_wasm_sync.js";
import { makeApi } from "./falcon-core";

const module = createModule();

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
