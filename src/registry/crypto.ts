/**
 * ClawOS Layer 5: Trust Registry — Cryptographic Utilities
 */

import { createHash, createVerify, type KeyObject } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import type { SignatureVerifyResult } from "./types.js";

// ============================================================================
// Hash Functions
// ============================================================================

/**
 * Calculate hash of content.
 */
export function calculateHash(
  content: Buffer | string,
  algorithm: "sha256" | "sha512" = "sha256"
): string {
  const hash = createHash(algorithm);
  hash.update(content);
  return hash.digest("hex");
}

/**
 * Calculate hash of a file.
 */
export async function hashFile(
  filePath: string,
  algorithm: "sha256" | "sha512" = "sha256"
): Promise<string> {
  const content = await readFile(filePath);
  return calculateHash(content, algorithm);
}

/**
 * Calculate deterministic hash of a directory.
 * Sorts files and hashes each, then hashes the combined result.
 */
export async function hashDirectory(
  dir: string,
  algorithm: "sha256" | "sha512" = "sha256"
): Promise<string> {
  const files = await walkDir(dir);
  files.sort();

  const hashes: string[] = [];
  for (const file of files) {
    const content = await readFile(file);
    const hash = calculateHash(content, algorithm);
    const relativePath = relative(dir, file);
    hashes.push(`${relativePath}:${hash}`);
  }

  return calculateHash(hashes.join("\n"), algorithm);
}

/**
 * Recursively walk a directory and return all file paths.
 */
async function walkDir(dir: string): Promise<string[]> {
  const files: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);

    // Skip hidden files and common non-code directories
    if (entry.name.startsWith(".") || entry.name === "node_modules") {
      continue;
    }

    if (entry.isDirectory()) {
      files.push(...(await walkDir(fullPath)));
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }

  return files;
}

/**
 * Compare two hashes in constant time to prevent timing attacks.
 */
export function compareHashes(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

// ============================================================================
// Signature Verification
// ============================================================================

/**
 * Verify a signature against content.
 */
export function verifySignature(
  content: Buffer | string,
  signature: string,
  publicKey: string,
  algorithm: "ed25519" | "rsa-sha256"
): SignatureVerifyResult {
  try {
    const verifyAlgorithm = algorithm === "ed25519" ? "ed25519" : "RSA-SHA256";
    const verify = createVerify(verifyAlgorithm);
    verify.update(content);

    const isValid = verify.verify(publicKey, signature, "base64");

    return {
      valid: isValid,
      algorithm,
      error: isValid ? undefined : "Signature verification failed",
    };
  } catch (err) {
    return {
      valid: false,
      algorithm,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Calculate fingerprint of a public key.
 */
export function calculateKeyFingerprint(publicKey: string): string {
  const hash = createHash("sha256");
  hash.update(publicKey);
  const digest = hash.digest("hex");

  // Format as colon-separated pairs for readability
  return digest.match(/.{2}/g)?.join(":").toUpperCase() || digest;
}

// ============================================================================
// Key Validation
// ============================================================================

/**
 * Check if a public key is valid.
 */
export function isValidPublicKey(publicKey: string): boolean {
  try {
    // Try to detect key format
    if (publicKey.includes("BEGIN PUBLIC KEY")) {
      // PEM format - basic validation
      return (
        publicKey.includes("-----BEGIN PUBLIC KEY-----") &&
        publicKey.includes("-----END PUBLIC KEY-----")
      );
    }

    // Base64 format - check if it decodes
    const decoded = Buffer.from(publicKey, "base64");
    return decoded.length > 0;
  } catch {
    return false;
  }
}

/**
 * Normalize a public key to PEM format if needed.
 */
export function normalizePublicKey(publicKey: string): string {
  if (publicKey.includes("BEGIN PUBLIC KEY")) {
    return publicKey;
  }

  // Assume base64, wrap in PEM
  const lines = publicKey.match(/.{1,64}/g) || [publicKey];
  return [
    "-----BEGIN PUBLIC KEY-----",
    ...lines,
    "-----END PUBLIC KEY-----",
  ].join("\n");
}
