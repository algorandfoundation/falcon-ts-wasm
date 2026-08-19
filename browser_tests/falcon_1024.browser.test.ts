import { test, expect } from "@playwright/test";

test.describe("Falcon Browser Tests", () => {
  test.describe("generateKey", () => {
    test("generates keys with correct sizes", async ({ page }) => {
      await page.goto("http://localhost:3123");

      const result = await page.evaluate(async () => {
        const { falcon1024, FALCON_DET1024_PUBKEY_SIZE, FALCON_DET1024_PRIVKEY_SIZE } =
          await import("/dist/index.js");
        const { generateKey } = falcon1024;

        const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
        const { publicKey, privateKey } = generateKey(seed);

        return {
          publicKeyLength: publicKey.length,
          privateKeyLength: privateKey.length,
          expectedPublicKeySize: FALCON_DET1024_PUBKEY_SIZE,
          expectedPrivateKeySize: FALCON_DET1024_PRIVKEY_SIZE,
        };
      });

      expect(result.publicKeyLength).toBe(result.expectedPublicKeySize);
      expect(result.privateKeyLength).toBe(result.expectedPrivateKeySize);
    });

    test("generates keys with empty seed", async ({ page }) => {
      await page.goto("http://localhost:3123");

      const result = await page.evaluate(async () => {
        const { falcon1024, FALCON_DET1024_PUBKEY_SIZE, FALCON_DET1024_PRIVKEY_SIZE } =
          await import("/dist/index.js");
        const { generateKey } = falcon1024;

        const { publicKey, privateKey } = generateKey();

        return {
          publicKeyLength: publicKey.length,
          privateKeyLength: privateKey.length,
          expectedPublicKeySize: FALCON_DET1024_PUBKEY_SIZE,
          expectedPrivateKeySize: FALCON_DET1024_PRIVKEY_SIZE,
        };
      });

      expect(result.publicKeyLength).toBe(result.expectedPublicKeySize);
      expect(result.privateKeyLength).toBe(result.expectedPrivateKeySize);
    });

    test("generates deterministic keys from same seed", async ({ page }) => {
      await page.goto("http://localhost:3123");

      const result = await page.evaluate(async () => {
        const { falcon1024 } = await import("/dist/index.js");
        const { generateKey } = falcon1024;

        const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
        const keys1 = generateKey(seed);
        const keys2 = generateKey(seed);

        return {
          publicKeysMatch:
            JSON.stringify(Array.from(keys1.publicKey)) ===
            JSON.stringify(Array.from(keys2.publicKey)),
          privateKeysMatch:
            JSON.stringify(Array.from(keys1.privateKey)) ===
            JSON.stringify(Array.from(keys2.privateKey)),
        };
      });

      expect(result.publicKeysMatch).toBe(true);
      expect(result.privateKeysMatch).toBe(true);
    });

    test("generates different keys from different seeds", async ({ page }) => {
      await page.goto("http://localhost:3123");

      const result = await page.evaluate(async () => {
        const { falcon1024 } = await import("/dist/index.js");
        const { generateKey } = falcon1024;

        const seed1 = new Uint8Array([1, 2, 3, 4]);
        const seed2 = new Uint8Array([5, 6, 7, 8]);
        const keys1 = generateKey(seed1);
        const keys2 = generateKey(seed2);

        return {
          publicKeysDiffer:
            JSON.stringify(Array.from(keys1.publicKey)) !==
            JSON.stringify(Array.from(keys2.publicKey)),
          privateKeysDiffer:
            JSON.stringify(Array.from(keys1.privateKey)) !==
            JSON.stringify(Array.from(keys2.privateKey)),
        };
      });

      expect(result.publicKeysDiffer).toBe(true);
      expect(result.privateKeysDiffer).toBe(true);
    });
  });

  test.describe("signCompressed", () => {
    test("produces a signature", async ({ page }) => {
      await page.goto("http://localhost:3123");

      const result = await page.evaluate(async () => {
        const { falcon1024 } = await import("/dist/index.js");
        const { generateKey, signCompressed } = falcon1024;

        const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
        const { privateKey } = generateKey(seed);
        const message = new TextEncoder().encode("Hello, Falcon!");

        const signature = signCompressed(privateKey, message);

        return {
          signatureLength: signature.length,
        };
      });

      expect(result.signatureLength).toBeGreaterThan(0);
      expect(result.signatureLength).toBeLessThanOrEqual(1330);
    });

    test("signs empty message", async ({ page }) => {
      await page.goto("http://localhost:3123");

      const result = await page.evaluate(async () => {
        const { falcon1024 } = await import("/dist/index.js");
        const { generateKey, signCompressed } = falcon1024;

        const { privateKey } = generateKey();
        const signature = signCompressed(privateKey, new Uint8Array(0));

        return {
          signatureLength: signature.length,
        };
      });

      expect(result.signatureLength).toBeGreaterThan(0);
    });

    test("produces deterministic signatures", async ({ page }) => {
      await page.goto("http://localhost:3123");

      const result = await page.evaluate(async () => {
        const { falcon1024 } = await import("/dist/index.js");
        const { generateKey, signCompressed } = falcon1024;

        const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
        const { privateKey } = generateKey(seed);
        const message = new TextEncoder().encode("Hello, Falcon!");

        const sig1 = signCompressed(privateKey, message);
        const sig2 = signCompressed(privateKey, message);

        return {
          signaturesMatch:
            JSON.stringify(Array.from(sig1)) ===
            JSON.stringify(Array.from(sig2)),
        };
      });

      expect(result.signaturesMatch).toBe(true);
    });
  });

  test.describe("verifyCompressed", () => {
    test("verifies valid signature", async ({ page }) => {
      await page.goto("http://localhost:3123");

      const result = await page.evaluate(async () => {
        const { falcon1024 } = await import("/dist/index.js");
        const { generateKey, signCompressed, verifyCompressed } = falcon1024;

        const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
        const { publicKey, privateKey } = generateKey(seed);
        const message = new TextEncoder().encode("Hello, Falcon!");
        const signature = signCompressed(privateKey, message);

        const isValid = verifyCompressed(publicKey, signature, message);

        return { isValid };
      });

      expect(result.isValid).toBe(true);
    });

    test("verifies empty message signature", async ({ page }) => {
      await page.goto("http://localhost:3123");

      const result = await page.evaluate(async () => {
        const { falcon1024 } = await import("/dist/index.js");
        const { generateKey, signCompressed, verifyCompressed } = falcon1024;

        const { publicKey, privateKey } = generateKey();
        const message = new Uint8Array(0);
        const signature = signCompressed(privateKey, message);

        const isValid = verifyCompressed(publicKey, signature, message);

        return { isValid };
      });

      expect(result.isValid).toBe(true);
    });

    test("rejects signature with wrong message", async ({ page }) => {
      await page.goto("http://localhost:3123");

      const result = await page.evaluate(async () => {
        const { falcon1024 } = await import("/dist/index.js");
        const { generateKey, signCompressed, verifyCompressed } = falcon1024;

        const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
        const { publicKey, privateKey } = generateKey(seed);
        const message = new TextEncoder().encode("Hello, Falcon!");
        const signature = signCompressed(privateKey, message);
        const wrongMessage = new TextEncoder().encode("Wrong message");

        try {
          verifyCompressed(publicKey, signature, wrongMessage);
          return { threw: false, errorName: null };
        } catch (e: any) {
          return { threw: true, errorName: e.name };
        }
      });

      expect(result.threw).toBe(true);
      expect(result.errorName).toBe("VerificaitonError");
    });

    test("rejects signature with wrong public key", async ({ page }) => {
      await page.goto("http://localhost:3123");

      const result = await page.evaluate(async () => {
        const { falcon1024 } = await import("/dist/index.js");
        const { generateKey, signCompressed, verifyCompressed } = falcon1024;

        const { privateKey } = generateKey(new Uint8Array([1, 2, 3, 4]));
        const { publicKey: wrongPublicKey } = generateKey(
          new Uint8Array([5, 6, 7, 8]),
        );
        const message = new TextEncoder().encode("Hello, Falcon!");
        const signature = signCompressed(privateKey, message);

        try {
          verifyCompressed(wrongPublicKey, signature, message);
          return { threw: false, errorName: null };
        } catch (e: any) {
          return { threw: true, errorName: e.name };
        }
      });

      expect(result.threw).toBe(true);
      expect(result.errorName).toBe("VerificaitonError");
    });

    test("rejects empty signature", async ({ page }) => {
      await page.goto("http://localhost:3123");

      const result = await page.evaluate(async () => {
        const { falcon1024 } = await import("/dist/index.js");
        const { generateKey, verifyCompressed } = falcon1024;

        const { publicKey } = generateKey();
        const message = new TextEncoder().encode("Hello, Falcon!");

        try {
          verifyCompressed(publicKey, new Uint8Array(0), message);
          return { threw: false, errorName: null };
        } catch (e: any) {
          return { threw: true, errorName: e.name };
        }
      });

      expect(result.threw).toBe(true);
      expect(result.errorName).toBe("VerificaitonError");
    });

    test("rejects corrupted signature", async ({ page }) => {
      await page.goto("http://localhost:3123");

      const result = await page.evaluate(async () => {
        const { falcon1024 } = await import("/dist/index.js");
        const { generateKey, signCompressed, verifyCompressed } = falcon1024;

        const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
        const { publicKey, privateKey } = generateKey(seed);
        const message = new TextEncoder().encode("Hello, Falcon!");
        const signature = signCompressed(privateKey, message);

        // Corrupt the signature
        const corruptedSig = new Uint8Array(signature);
        corruptedSig[100]! ^= 0xff;

        try {
          verifyCompressed(publicKey, corruptedSig, message);
          return { threw: false, errorName: null };
        } catch (e: any) {
          return { threw: true, errorName: e.name };
        }
      });

      expect(result.threw).toBe(true);
      expect(result.errorName).toBe("VerificaitonError");
    });
  });
});
