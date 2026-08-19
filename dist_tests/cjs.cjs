// Consumes the built CJS bundle (dist/index.cjs) via a real `require`, the same
// way a CommonJS consumer of the published package would. Run with `node --test`
// after `pnpm run build`. Keep this in sync with esm.mjs.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  falcon1024,
  VerificationError,
  FALCON_DET1024_PUBKEY_SIZE,
  FALCON_DET1024_PRIVKEY_SIZE,
} = require("../dist/index.cjs");

const { generateKey, signCompressed, verifyCompressed } = falcon1024;

const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
const message = new TextEncoder().encode("Hello, Falcon!");

test("CJS: generates keys with correct sizes", () => {
  const { publicKey, privateKey } = generateKey(seed);
  assert.equal(publicKey.length, FALCON_DET1024_PUBKEY_SIZE);
  assert.equal(privateKey.length, FALCON_DET1024_PRIVKEY_SIZE);
});

test("CJS: signs and verifies a valid signature", () => {
  const { publicKey, privateKey } = generateKey(seed);
  const signature = signCompressed(privateKey, message);
  assert.ok(signature.length > 0);
  assert.equal(verifyCompressed(publicKey, signature, message), true);
});

test("CJS: rejects a signature for the wrong message", () => {
  const { publicKey, privateKey } = generateKey(seed);
  const signature = signCompressed(privateKey, message);
  const wrongMessage = new TextEncoder().encode("Wrong message");
  assert.throws(
    () => verifyCompressed(publicKey, signature, wrongMessage),
    VerificationError,
  );
});
