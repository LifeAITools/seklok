import { describe, test, expect } from "bun:test";
import {
  generateKeyB64,
  encrypt,
  decrypt,
  hashStringSha256,
  isBase64,
} from "../src/lib/encryption.js";

describe("Encryption", () => {
  test("round-trip: encrypt then decrypt returns original", () => {
    const key = generateKeyB64();
    const plaintext = "hello world";
    const { cipheredData, iv } = encrypt(key, plaintext);
    const result = decrypt(key, cipheredData, iv);
    expect(result).toBe(plaintext);
  });

  test("round-trip with empty string", () => {
    const key = generateKeyB64();
    const { cipheredData, iv } = encrypt(key, "");
    expect(decrypt(key, cipheredData, iv)).toBe("");
  });

  test("round-trip with unicode", () => {
    const key = generateKeyB64();
    const plaintext = "Привет мир 🌍 日本語テスト";
    const { cipheredData, iv } = encrypt(key, plaintext);
    expect(decrypt(key, cipheredData, iv)).toBe(plaintext);
  });

  test("round-trip with long string (1000 chars)", () => {
    const key = generateKeyB64();
    const plaintext = "A".repeat(1000);
    const { cipheredData, iv } = encrypt(key, plaintext);
    expect(decrypt(key, cipheredData, iv)).toBe(plaintext);
  });

  test("round-trip with special chars", () => {
    const key = generateKeyB64();
    const plaintext = '!@#$%^&*()_+-=[]{}|;:\'",.<>?/\\`~\n\t\r';
    const { cipheredData, iv } = encrypt(key, plaintext);
    expect(decrypt(key, cipheredData, iv)).toBe(plaintext);
  });

  test("key generation: 100 keys all unique, valid base64, decode to 32 bytes", () => {
    const keys = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const key = generateKeyB64();
      keys.add(key);
      expect(isBase64(key)).toBe(true);
      expect(Buffer.from(key, "base64").length).toBe(32);
    }
    expect(keys.size).toBe(100);
  });

  test("SHA-256 produces known hash for 'test'", () => {
    const hash = hashStringSha256("test");
    expect(hash).toBe(
      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    );
  });

  test("isBase64: valid base64 returns true", () => {
    expect(isBase64(Buffer.from("hello").toString("base64"))).toBe(true);
    expect(isBase64(generateKeyB64())).toBe(true);
  });

  test("isBase64: invalid base64 returns false", () => {
    expect(isBase64("not-base64!!!")).toBe(false);
  });

  test("isBase64: empty string returns false", () => {
    expect(isBase64("")).toBe(false);
  });

  test("different keys produce different ciphertext", () => {
    const keyA = generateKeyB64();
    const keyB = generateKeyB64();
    const plaintext = "same plaintext";
    const encA = encrypt(keyA, plaintext);
    const encB = encrypt(keyB, plaintext);
    expect(encA.cipheredData).not.toBe(encB.cipheredData);
  });

  test("wrong key decrypt throws error", () => {
    const keyA = generateKeyB64();
    const keyB = generateKeyB64();
    const { cipheredData, iv } = encrypt(keyA, "secret data");
    expect(() => decrypt(keyB, cipheredData, iv)).toThrow();
  });

  test("IV uniqueness: same key + same plaintext produces different ciphertext", () => {
    const key = generateKeyB64();
    const plaintext = "identical plaintext";
    const enc1 = encrypt(key, plaintext);
    const enc2 = encrypt(key, plaintext);
    expect(enc1.cipheredData).not.toBe(enc2.cipheredData);
    expect(enc1.iv).not.toBe(enc2.iv);
    // Both still decrypt to same value
    expect(decrypt(key, enc1.cipheredData, enc1.iv)).toBe(plaintext);
    expect(decrypt(key, enc2.cipheredData, enc2.iv)).toBe(plaintext);
  });
});
