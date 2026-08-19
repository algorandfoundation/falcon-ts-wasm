// Consumes the built ESM bundle (dist/index.js) via a real `import`, the same
// way an ESM consumer of the published package would. Run with `node --test`
// after `pnpm run build`. Keep this in sync with cjs.cjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  falcon1024,
  VerificationError,
  FALCON_DET1024_PUBKEY_SIZE,
  FALCON_DET1024_PRIVKEY_SIZE,
} from "../dist/index.js";

const { generateKey, signCompressed, verifyCompressed } = falcon1024;

const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
const message = new TextEncoder().encode("Hello, Falcon!");

test("ESM: generates keys with correct sizes", () => {
  const { publicKey, privateKey } = generateKey(seed);
  assert.equal(publicKey.length, FALCON_DET1024_PUBKEY_SIZE);
  assert.equal(privateKey.length, FALCON_DET1024_PRIVKEY_SIZE);
});

test("ESM: signs and verifies a valid signature", () => {
  const { publicKey, privateKey } = generateKey(seed);
  const signature = signCompressed(privateKey, message);
  assert.ok(signature.length > 0);
  assert.equal(verifyCompressed(publicKey, signature, message), true);
});

test("ESM: rejects a signature for the wrong message", () => {
  const { publicKey, privateKey } = generateKey(seed);
  const signature = signCompressed(privateKey, message);
  const wrongMessage = new TextEncoder().encode("Wrong message");
  assert.throws(
    () => verifyCompressed(publicKey, signature, wrongMessage),
    VerificationError,
  );
});
