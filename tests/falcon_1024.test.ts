import { describe, test, expect } from "vitest";
import {
  falcon1024,
  SigningError,
  VerificationError,
  FALCON_DET1024_PUBKEY_SIZE,
  FALCON_DET1024_PRIVKEY_SIZE,
  FALCON_DET1024_SIG_COMPRESSED_HEADER,
  FALCON1024_SIG_COMPRESSED_MAXSIZE,
  FALCON1024_SIG_COMPRESSED_HEADER,
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

  describe("signCompressed (randomized)", () => {
    const { publicKey, privateKey } = generateKey(
      new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
    );
    const message = new TextEncoder().encode("Hello, Falcon!");

    test("is deterministic by default", () => {
      expect(signCompressed(privateKey, message)[0]).toBe(
        FALCON_DET1024_SIG_COMPRESSED_HEADER,
      );
      expect(signCompressed(privateKey, message, false)).toEqual(
        signCompressed(privateKey, message),
      );
    });

    test("produces a randomized compressed signature", () => {
      const signature = signCompressed(privateKey, message, true);

      expect(signature[0]).toBe(FALCON1024_SIG_COMPRESSED_HEADER);
      expect(signature.length).toBeGreaterThan(41);
      expect(signature.length).toBeLessThanOrEqual(
        FALCON1024_SIG_COMPRESSED_MAXSIZE,
      );
    });

    test("produces different signatures for the same message", () => {
      const sig1 = signCompressed(privateKey, message, true);
      const sig2 = signCompressed(privateKey, message, true);

      expect(sig1).not.toEqual(sig2);
    });

    test("signs and verifies empty message", () => {
      const empty = new Uint8Array(0);
      const signature = signCompressed(privateKey, empty, true);

      expect(signature[0]).toBe(FALCON1024_SIG_COMPRESSED_HEADER);
      expect(verifyCompressed(publicKey, signature, empty)).toBe(true);
    });

    test("rejects invalid private key length", () => {
      expect(() => {
        signCompressed(new Uint8Array(10), message, true);
      }).toThrow(SigningError);
    });
  });

  describe("verifyCompressed (header dispatch)", () => {
    const { publicKey, privateKey } = generateKey(
      new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
    );
    const message = new TextEncoder().encode("Hello, Falcon!");
    const wrongMessage = new TextEncoder().encode("Wrong message");

    test("accepts randomized signatures", () => {
      const signature = signCompressed(privateKey, message, true);

      expect(verifyCompressed(publicKey, signature, message)).toBe(true);
    });

    test("rejects wrong message for both modes", () => {
      expect(() => {
        verifyCompressed(
          publicKey,
          signCompressed(privateKey, message),
          wrongMessage,
        );
      }).toThrow(VerificationError);
      expect(() => {
        verifyCompressed(
          publicKey,
          signCompressed(privateKey, message, true),
          wrongMessage,
        );
      }).toThrow(VerificationError);
    });

    test("rejects corrupted randomized signature", () => {
      const signature = signCompressed(privateKey, message, true);
      signature[100]! ^= 0xff;

      expect(() => {
        verifyCompressed(publicKey, signature, message);
      }).toThrow(VerificationError);
    });

    test("rejects a randomized signature relabelled as deterministic", () => {
      const signature = signCompressed(privateKey, message, true);
      signature[0] = FALCON_DET1024_SIG_COMPRESSED_HEADER;

      expect(() => {
        verifyCompressed(publicKey, signature, message);
      }).toThrow(VerificationError);
    });

    test("rejects a deterministic signature relabelled as randomized", () => {
      const signature = signCompressed(privateKey, message);
      signature[0] = FALCON1024_SIG_COMPRESSED_HEADER;

      expect(() => {
        verifyCompressed(publicKey, signature, message);
      }).toThrow(VerificationError);
    });

    test("rejects oversized randomized signature", () => {
      const signature = new Uint8Array(FALCON1024_SIG_COMPRESSED_MAXSIZE + 1);
      signature[0] = FALCON1024_SIG_COMPRESSED_HEADER;

      expect(() => {
        verifyCompressed(publicKey, signature, message);
      }).toThrow(/Invalid signature length/);
    });

    test("rejects unknown header", () => {
      const signature = signCompressed(privateKey, message, true);
      signature[0] = 0x5a; // randomized CT header, not supported here

      expect(() => {
        verifyCompressed(publicKey, signature, message);
      }).toThrow("invalid format");
    });
  });
});
