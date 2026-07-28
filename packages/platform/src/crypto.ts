import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { errors } from '@sentinel/core';

/**
 * Envelope encryption for stored integration tokens.
 *
 * Sentinel stores GitHub tokens so it can re-scan private repositories. Those
 * are live credentials for someone else's source code, so they are encrypted at
 * rest with AES-256-GCM — authenticated, so a tampered ciphertext fails loudly
 * instead of decrypting to attacker-chosen bytes.
 */

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits, the value GCM is specified for
const SALT_LENGTH = 16;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;

/**
 * Derive a key with scrypt.
 *
 * A per-ciphertext salt means two encryptions of the same value under the same
 * master key produce unrelated keys, and scrypt's memory hardness makes an
 * offline attack on a leaked master key expensive.
 */
function deriveKey(masterKey: string, salt: Buffer): Buffer {
  return scryptSync(masterKey, salt, KEY_LENGTH, { N: 16_384, r: 8, p: 1 });
}

/**
 * Encrypt to a self-describing blob: `salt || iv || tag || ciphertext`, base64.
 * Everything needed to decrypt except the master key travels with the value, so
 * key rotation is the only operational concern.
 */
export function encryptSecret(plaintext: string, masterKey: string): string {
  if (!masterKey || masterKey.length < 32) {
    throw errors.internal('ENCRYPTION_KEY must be at least 32 characters');
  }

  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, deriveKey(masterKey, salt), iv);

  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([salt, iv, cipher.getAuthTag(), ciphertext]).toString('base64');
}

export function decryptSecret(encoded: string, masterKey: string): string {
  if (!masterKey || masterKey.length < 32) {
    throw errors.internal('ENCRYPTION_KEY must be at least 32 characters');
  }

  const blob = Buffer.from(encoded, 'base64');
  if (blob.length < SALT_LENGTH + IV_LENGTH + TAG_LENGTH) {
    throw errors.validation('Encrypted value is malformed');
  }

  const salt = blob.subarray(0, SALT_LENGTH);
  const iv = blob.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const tag = blob.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
  const ciphertext = blob.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);

  const decipher = createDecipheriv(ALGORITHM, deriveKey(masterKey, salt), iv);
  decipher.setAuthTag(tag);

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    // GCM authentication failed: the value was tampered with, or the key changed.
    throw errors.validation(
      'Unable to decrypt value: it was modified or the encryption key changed',
    );
  }
}

/**
 * Verify a webhook signature in constant time.
 *
 * GitHub signs webhook bodies with HMAC-SHA256. Comparing with `===` leaks the
 * correct prefix through timing, which is enough to forge a signature given
 * enough attempts.
 */
export async function verifyWebhookSignature(
  body: string,
  signatureHeader: string | null,
  secret: string,
): Promise<boolean> {
  if (!signatureHeader || !secret) return false;

  const { createHmac, timingSafeEqual } = await import('node:crypto');
  const expected = `sha256=${createHmac('sha256', secret).update(body, 'utf8').digest('hex')}`;

  const provided = Buffer.from(signatureHeader);
  const computed = Buffer.from(expected);
  if (provided.length !== computed.length) return false;
  return timingSafeEqual(provided, computed);
}
