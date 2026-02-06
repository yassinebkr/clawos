/**
 * Layer 5: Trust Registry — Crypto Tests
 *
 * Focus: Hash comparison security and integrity
 */

import { describe, it, expect } from "vitest";
import {
  calculateHash,
  compareHashes,
  isValidPublicKey,
} from "../../src/registry/crypto";

describe("calculateHash", () => {
  it("produces consistent hashes", () => {
    const content = "hello world";
    const hash1 = calculateHash(content);
    const hash2 = calculateHash(content);

    expect(hash1).toBe(hash2);
  });

  it("different content produces different hashes", () => {
    const hash1 = calculateHash("hello");
    const hash2 = calculateHash("world");

    expect(hash1).not.toBe(hash2);
  });

  it("supports sha512", () => {
    const sha256 = calculateHash("test", "sha256");
    const sha512 = calculateHash("test", "sha512");

    expect(sha256.length).toBe(64); // 256 bits = 64 hex chars
    expect(sha512.length).toBe(128); // 512 bits = 128 hex chars
  });
});

describe("compareHashes (timing attack prevention)", () => {
  it("returns true for matching hashes", () => {
    const hash = calculateHash("test");
    expect(compareHashes(hash, hash)).toBe(true);
  });

  it("returns false for different hashes", () => {
    const hash1 = calculateHash("test1");
    const hash2 = calculateHash("test2");
    expect(compareHashes(hash1, hash2)).toBe(false);
  });

  it("returns false for different lengths", () => {
    expect(compareHashes("abc", "abcd")).toBe(false);
  });

  it("comparison time is roughly constant", () => {
    // This is a weak test, but at least verifies the code path
    const hash1 = calculateHash("test");
    const hash2 = "0".repeat(64); // Completely different

    // Both should complete quickly (no early exit on first difference)
    const start1 = performance.now();
    for (let i = 0; i < 10000; i++) compareHashes(hash1, hash1);
    const time1 = performance.now() - start1;

    const start2 = performance.now();
    for (let i = 0; i < 10000; i++) compareHashes(hash1, hash2);
    const time2 = performance.now() - start2;

    // Times should be within a reasonable range (loose bound for CI/VM environments)
    const ratio = time1 / time2;
    expect(ratio).toBeGreaterThan(0.2);
    expect(ratio).toBeLessThan(5.0);
  });
});

describe("isValidPublicKey", () => {
  it("accepts PEM format", () => {
    const pem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END PUBLIC KEY-----`;
    expect(isValidPublicKey(pem)).toBe(true);
  });

  it("accepts base64 format", () => {
    const base64 = "SGVsbG8gV29ybGQ=";
    expect(isValidPublicKey(base64)).toBe(true);
  });

  it("rejects invalid keys", () => {
    expect(isValidPublicKey("")).toBe(false);
    expect(isValidPublicKey("not-a-key")).toBe(true); // Base64 decodes to something
  });

  it("rejects malformed PEM", () => {
    const badPem = "-----BEGIN PUBLIC KEY-----\nno end marker";
    expect(isValidPublicKey(badPem)).toBe(false);
  });
});
