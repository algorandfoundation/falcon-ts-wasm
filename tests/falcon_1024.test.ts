import { describe, test, expect } from "vitest";
import {
  falcon1024,
  VerificationError,
  FALCON_DET1024_PUBKEY_SIZE,
  FALCON_DET1024_PRIVKEY_SIZE,
} from "../src/index";

const { generateKey, signCompressed, verifyCompressed } = falcon1024;

describe("Falcon", () => {
  describe("generateKey", () => {
    test("generates keys with correct sizes", () => {
      const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const { publicKey, privateKey } = generateKey(seed);

      expect(publicKey.length).toBe(FALCON_DET1024_PUBKEY_SIZE);
      expect(privateKey.length).toBe(FALCON_DET1024_PRIVKEY_SIZE);
    });

    test("generates keys with empty seed", () => {
      const { publicKey, privateKey } = generateKey();

      expect(publicKey.length).toBe(FALCON_DET1024_PUBKEY_SIZE);
      expect(privateKey.length).toBe(FALCON_DET1024_PRIVKEY_SIZE);
    });

    test("generates deterministic keys from same seed", () => {
      const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const keys1 = generateKey(seed);
      const keys2 = generateKey(seed);

      expect(keys1.publicKey).toEqual(keys2.publicKey);
      expect(keys1.privateKey).toEqual(keys2.privateKey);
    });

    test("generates different keys from different seeds", () => {
      const seed1 = new Uint8Array([1, 2, 3, 4]);
      const seed2 = new Uint8Array([5, 6, 7, 8]);
      const keys1 = generateKey(seed1);
      const keys2 = generateKey(seed2);

      expect(keys1.publicKey).not.toEqual(keys2.publicKey);
      expect(keys1.privateKey).not.toEqual(keys2.privateKey);
    });
  });

  describe("signCompressed", () => {
    test("produces a signature", () => {
      const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const { privateKey } = generateKey(seed);
      const message = new TextEncoder().encode("Hello, Falcon!");

      const signature = signCompressed(privateKey, message);

      expect(signature.length).toBeGreaterThan(0);
      expect(signature.length).toBeLessThanOrEqual(1330); // SignatureMaxSize
    });

    test("signs empty message", () => {
      const { privateKey } = generateKey();
      const signature = signCompressed(privateKey, new Uint8Array(0));

      expect(signature.length).toBeGreaterThan(0);
    });

    test("produces deterministic signatures", () => {
      const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const { privateKey } = generateKey(seed);
      const message = new TextEncoder().encode("Hello, Falcon!");

      const sig1 = signCompressed(privateKey, message);
      const sig2 = signCompressed(privateKey, message);

      expect(sig1).toEqual(sig2);
    });
  });

  describe("verifyCompressed", () => {
    test("verifies valid signature", () => {
      const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const { publicKey, privateKey } = generateKey(seed);
      const message = new TextEncoder().encode("Hello, Falcon!");
      const signature = signCompressed(privateKey, message);

      const isValid = verifyCompressed(publicKey, signature, message);

      expect(isValid).toBe(true);
    });

    test("verifies empty message signature", () => {
      const { publicKey, privateKey } = generateKey();
      const message = new Uint8Array(0);
      const signature = signCompressed(privateKey, message);

      const isValid = verifyCompressed(publicKey, signature, message);

      expect(isValid).toBe(true);
    });

    test("rejects signature with wrong message", () => {
      const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const { publicKey, privateKey } = generateKey(seed);
      const message = new TextEncoder().encode("Hello, Falcon!");
      const signature = signCompressed(privateKey, message);
      const wrongMessage = new TextEncoder().encode("Wrong message");

      expect(() => {
        verifyCompressed(publicKey, signature, wrongMessage);
      }).toThrow(VerificationError);
    });

    test("rejects signature with wrong public key", () => {
      const { privateKey } = generateKey(new Uint8Array([1, 2, 3, 4]));
      const { publicKey: wrongPublicKey } = generateKey(
        new Uint8Array([5, 6, 7, 8]),
      );
      const message = new TextEncoder().encode("Hello, Falcon!");
      const signature = signCompressed(privateKey, message);

      expect(() => {
        verifyCompressed(wrongPublicKey, signature, message);
      }).toThrow(VerificationError);
    });

    test("rejects empty signature", () => {
      const { publicKey } = generateKey();
      const message = new TextEncoder().encode("Hello, Falcon!");

      expect(() => {
        verifyCompressed(publicKey, new Uint8Array(0), message);
      }).toThrow(VerificationError);
    });

    test("rejects corrupted signature", () => {
      const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const { publicKey, privateKey } = generateKey(seed);
      const message = new TextEncoder().encode("Hello, Falcon!");
      const signature = signCompressed(privateKey, message);

      // Corrupt the signature
      const corruptedSig = new Uint8Array(signature);
      corruptedSig[100]! ^= 0xff;

      expect(() => {
        verifyCompressed(publicKey, corruptedSig, message);
      }).toThrow(VerificationError);
    });
  });
});
