/**
 * rookery browser crypto module — Phase 0 stub.
 *
 * This module will grow in Phase 1 to include:
 *   - In-browser PGP key generation (Curve25519 via OpenPGP.js)
 *   - Argon2id passphrase-to-key derivation (WASM)
 *   - Private key storage in IndexedDB (passphrase-encrypted)
 *   - PGP/MIME encrypt + sign on compose page
 *   - PGP/MIME decrypt + verify signature on read page
 *
 * See §6, §11.1 of PLAN.md and ADR-0010, ADR-0011.
 *
 * Dependencies added in Phase 1:
 *   - openpgp (OpenPGP.js) — pinned, SRI-locked, vendored
 *   - argon2-browser (WASM Argon2id) — pinned, SRI-locked
 *
 * This file is bundled by esbuild inside the Containerfile build (Stage 2).
 * It is never run directly by Node in production.
 */

export const ROOKERY_CRYPTO_VERSION = "0.0.0-phase0";

// Phase 0: nothing to do. Real implementation lands in Phase 1.
