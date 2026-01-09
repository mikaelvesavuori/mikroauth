import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync
} from 'node:crypto';

/**
 * @description Encryption utility for securing data at rest.
 * Uses AES-256-GCM for authenticated encryption with associated data.
 */
export class Encryption {
  private readonly key: Buffer;
  private readonly algorithm = 'aes-256-gcm';
  private readonly keyLength = 32; // 256 bits

  constructor(password: string) {
    // Derive a 256-bit key from the password using scrypt
    this.key = scryptSync(password, 'mikroauth-salt', this.keyLength);
  }

  /**
   * @description Encrypt a string value.
   * @param plaintext - The text to encrypt
   * @returns Encrypted data in format: iv:authTag:ciphertext (all hex-encoded)
   */
  encrypt(plaintext: string): string {
    const iv = randomBytes(12); // GCM standard: 12 bytes
    const cipher = createCipheriv(this.algorithm, this.key, iv);

    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final()
    ]);

    const authTag = cipher.getAuthTag();

    // Format: iv:authTag:encrypted (all hex-encoded for storage)
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  /**
   * @description Decrypt an encrypted string.
   * @param ciphertext - The encrypted data in format: iv:authTag:ciphertext
   * @returns Decrypted plaintext
   * @throws Error if decryption fails (invalid key, corrupted data, etc.)
   */
  decrypt(ciphertext: string): string {
    const parts = ciphertext.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format');
    }

    const [ivHex, authTagHex, encryptedHex] = parts;

    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');

    const decipher = createDecipheriv(this.algorithm, this.key, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]);

    return decrypted.toString('utf8');
  }
}
