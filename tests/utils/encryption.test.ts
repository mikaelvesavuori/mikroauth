import { describe, expect, test } from 'vitest';

import { Encryption } from '../../src/utils/encryption.js';

describe('Encryption', () => {
  test('It should encrypt and decrypt values correctly', () => {
    const encryption = new Encryption('my-secret-key');
    const plaintext = 'sensitive data';

    const encrypted = encryption.encrypt(plaintext);
    const decrypted = encryption.decrypt(encrypted);

    expect(decrypted).toBe(plaintext);
  });

  test('It should produce different ciphertext for the same plaintext', () => {
    const encryption = new Encryption('my-secret-key');
    const plaintext = 'test data';

    const encrypted1 = encryption.encrypt(plaintext);
    const encrypted2 = encryption.encrypt(plaintext);

    // Different IVs should produce different ciphertext
    expect(encrypted1).not.toBe(encrypted2);

    // But both should decrypt to the same plaintext
    expect(encryption.decrypt(encrypted1)).toBe(plaintext);
    expect(encryption.decrypt(encrypted2)).toBe(plaintext);
  });

  test('It should handle unicode characters', () => {
    const encryption = new Encryption('test-key');
    const plaintext = 'Hello 世界 🌍 مرحبا';

    const encrypted = encryption.encrypt(plaintext);
    const decrypted = encryption.decrypt(encrypted);

    expect(decrypted).toBe(plaintext);
  });

  test('It should handle empty strings', () => {
    const encryption = new Encryption('test-key');
    const plaintext = '';

    const encrypted = encryption.encrypt(plaintext);
    const decrypted = encryption.decrypt(encrypted);

    expect(decrypted).toBe(plaintext);
  });

  test('It should handle special characters', () => {
    const encryption = new Encryption('test-key');
    const plaintext = '!@#$%^&*()_+-=[]{}|;:\'",.<>?/~`';

    const encrypted = encryption.encrypt(plaintext);
    const decrypted = encryption.decrypt(encrypted);

    expect(decrypted).toBe(plaintext);
  });

  test('It should handle large strings', () => {
    const encryption = new Encryption('test-key');
    const plaintext = 'x'.repeat(10000);

    const encrypted = encryption.encrypt(plaintext);
    const decrypted = encryption.decrypt(encrypted);

    expect(decrypted).toBe(plaintext);
  });

  test('It should handle JSON data', () => {
    const encryption = new Encryption('test-key');
    const data = { user: 'test@example.com', id: 123, active: true };
    const plaintext = JSON.stringify(data);

    const encrypted = encryption.encrypt(plaintext);
    const decrypted = encryption.decrypt(encrypted);

    expect(JSON.parse(decrypted)).toEqual(data);
  });

  test('It should produce encrypted output in correct format', () => {
    const encryption = new Encryption('test-key');
    const encrypted = encryption.encrypt('test');

    // Should be in format: iv:authTag:ciphertext
    const parts = encrypted.split(':');
    expect(parts).toHaveLength(3);

    // Each part should be hex-encoded
    expect(parts[0]).toMatch(/^[0-9a-f]+$/); // IV
    expect(parts[1]).toMatch(/^[0-9a-f]+$/); // Auth tag
    expect(parts[2]).toMatch(/^[0-9a-f]+$/); // Ciphertext
  });

  test('It should fail to decrypt with wrong key', () => {
    const encryption1 = new Encryption('key1');
    const encryption2 = new Encryption('key2');

    const plaintext = 'secret data';
    const encrypted = encryption1.encrypt(plaintext);

    // Attempting to decrypt with wrong key should throw
    expect(() => encryption2.decrypt(encrypted)).toThrow();
  });

  test('It should fail to decrypt corrupted data', () => {
    const encryption = new Encryption('test-key');

    // Invalid format (missing parts)
    expect(() => encryption.decrypt('invalid')).toThrow(
      'Invalid encrypted data format'
    );
    expect(() => encryption.decrypt('part1:part2')).toThrow(
      'Invalid encrypted data format'
    );

    // Valid format but corrupted data
    const validEncrypted = encryption.encrypt('test');
    const parts = validEncrypted.split(':');
    const corrupted = `${parts[0]}:${parts[1]}:0000${parts[2]}`;

    expect(() => encryption.decrypt(corrupted)).toThrow();
  });

  test('It should fail to decrypt tampered ciphertext', () => {
    const encryption = new Encryption('test-key');
    const encrypted = encryption.encrypt('original data');

    // Tamper with the ciphertext
    const parts = encrypted.split(':');
    const tampered = `${parts[0]}:${parts[1]}:ff${parts[2].substring(2)}`;

    // GCM authentication should detect tampering
    expect(() => encryption.decrypt(tampered)).toThrow();
  });

  test('It should fail to decrypt tampered auth tag', () => {
    const encryption = new Encryption('test-key');
    const encrypted = encryption.encrypt('secure data');

    // Tamper with the auth tag
    const parts = encrypted.split(':');
    const tampered = `${parts[0]}:00${parts[1].substring(2)}:${parts[2]}`;

    expect(() => encryption.decrypt(tampered)).toThrow();
  });

  test('Different passwords should produce different keys', () => {
    const encryption1 = new Encryption('password1');
    const encryption2 = new Encryption('password2');

    const plaintext = 'test data';
    const encrypted1 = encryption1.encrypt(plaintext);

    // Should not be able to decrypt with different password
    expect(() => encryption2.decrypt(encrypted1)).toThrow();
  });

  test('Same password should consistently encrypt/decrypt', () => {
    const encryption1 = new Encryption('same-password');
    const encryption2 = new Encryption('same-password');

    const plaintext = 'test data';
    const encrypted = encryption1.encrypt(plaintext);
    const decrypted = encryption2.decrypt(encrypted);

    expect(decrypted).toBe(plaintext);
  });
});
