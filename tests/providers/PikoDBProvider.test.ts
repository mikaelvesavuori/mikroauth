import { existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { PikoDB } from 'pikodb';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import { PikoDBProvider } from '../../src/providers/PikoDBProvider.js';

const TEST_DB_DIR = join(process.cwd(), 'mikroauth-test-pikodb');
const TEST_ENCRYPTION_KEY = 'test-encryption-key-12345';

let storage: PikoDBProvider;
let storageWithEncryption: PikoDBProvider;

const wait = (seconds: number) =>
  new Promise((resolve) => setTimeout(resolve, seconds * 1000));

beforeEach(async () => {
  if (existsSync(TEST_DB_DIR))
    rmSync(TEST_DB_DIR, { recursive: true, force: true });

  // Storage without encryption
  const db = new PikoDB({
    databaseDirectory: TEST_DB_DIR
  });
  const pikodb = new PikoDBProvider(db);
  await pikodb.start();
  storage = pikodb;

  // Storage with encryption
  const dbEncrypted = new PikoDB({
    databaseDirectory: `${TEST_DB_DIR}-encrypted`
  });
  const pikodbEncrypted = new PikoDBProvider(dbEncrypted, TEST_ENCRYPTION_KEY);
  await pikodbEncrypted.start();
  storageWithEncryption = pikodbEncrypted;
});

afterEach(async () => {
  await storage.close();
  await storageWithEncryption.close();

  await wait(0.05);

  if (existsSync(TEST_DB_DIR))
    rmSync(TEST_DB_DIR, { recursive: true, force: true });

  if (existsSync(`${TEST_DB_DIR}-encrypted`))
    rmSync(`${TEST_DB_DIR}-encrypted`, { recursive: true, force: true });

  vi.restoreAllMocks();
});

describe('Key-value operations', () => {
  test('It should set and get values', async () => {
    await storage.set('key1', 'value1');
    expect(await storage.get('key1')).toBe('value1');

    expect(await storage.get('non-existent')).toBeNull();
  });

  test('It should delete values', async () => {
    await storage.set('key1', 'value1');
    expect(await storage.get('key1')).toBe('value1');
    await storage.delete('key1');
    expect(await storage.get('key1')).toBeNull();
  });

  test('It should handle value expiration', async () => {
    await storage.set('expiring-key', 'value', 0.1); // 0.1 second expiry

    expect(await storage.get('expiring-key')).toBe('value');

    await wait(0.2);

    expect(await storage.get('expiring-key')).toBeNull();
  });
});

describe('Key-value operations with encryption', () => {
  test('It should set and get encrypted values', async () => {
    await storageWithEncryption.set('key1', 'sensitive-value');
    const result = await storageWithEncryption.get('key1');
    expect(result).toBe('sensitive-value');
  });

  test('It should encrypt data at rest', async () => {
    await storageWithEncryption.set('key1', 'plaintext-value');

    // Access the raw database to verify encryption
    const db = (storageWithEncryption as any).db;
    const rawValue = await db.get('mikroauth', 'kv:key1');

    // Raw value should not equal plaintext (it should be encrypted)
    expect(rawValue).not.toBe('plaintext-value');
    expect(rawValue).toContain(':'); // Encrypted format contains colons

    // But decrypted value should be correct
    const decrypted = await storageWithEncryption.get('key1');
    expect(decrypted).toBe('plaintext-value');
  });

  test('It should handle encrypted values with expiration', async () => {
    await storageWithEncryption.set('expiring-key', 'secret', 0.1);

    expect(await storageWithEncryption.get('expiring-key')).toBe('secret');

    await wait(0.2);

    expect(await storageWithEncryption.get('expiring-key')).toBeNull();
  });
});

describe('Collection operations', () => {
  test('It should add and retrieve items from a collection', async () => {
    await storage.addToCollection('users', 'user1');
    await storage.addToCollection('users', 'user2');

    const users = await storage.getCollection('users');
    expect(users).toHaveLength(2);
    expect(users).toContain('user1');
    expect(users).toContain('user2');
  });

  test('It should get collection size', async () => {
    await storage.addToCollection('users', 'user1');
    await storage.addToCollection('users', 'user2');

    expect(await storage.getCollectionSize('users')).toBe(2);
    expect(await storage.getCollectionSize('empty')).toBe(0);
  });

  test('It should remove items from a collection', async () => {
    await storage.addToCollection('users', 'user1');
    await storage.addToCollection('users', 'user2');
    await storage.addToCollection('users', 'user3');

    await storage.removeFromCollection('users', 'user2');

    const users = await storage.getCollection('users');
    expect(users).toHaveLength(2);
    expect(users).toContain('user1');
    expect(users).toContain('user3');
    expect(users).not.toContain('user2');
  });

  test('It should remove the oldest item from a collection', async () => {
    await storage.addToCollection('users', 'user1');

    await wait(0.2);

    await storage.addToCollection('users', 'user2');

    const oldest = await storage.removeOldestFromCollection('users');
    expect(oldest).toBe('user1');

    const users = await storage.getCollection('users');
    expect(users).toHaveLength(1);
    expect(users).toContain('user2');
    expect(users).not.toContain('user1');
  });

  test('It should handle collection expiration', async () => {
    await storage.addToCollection('expiring-collection', 'item1', 0.1);

    expect(await storage.getCollectionSize('expiring-collection')).toBe(1);

    await wait(0.2);

    expect(await storage.getCollectionSize('expiring-collection')).toBe(0);
  });

  test('It should not add duplicate items to a collection', async () => {
    await storage.addToCollection('users', 'user1');
    await storage.addToCollection('users', 'user1');
    await storage.addToCollection('users', 'user1');

    const users = await storage.getCollection('users');
    expect(users).toHaveLength(1);
    expect(users).toContain('user1');
  });
});

describe('Collection operations with encryption', () => {
  test('It should handle encrypted collections', async () => {
    await storageWithEncryption.addToCollection('sessions', 'session1');
    await storageWithEncryption.addToCollection('sessions', 'session2');

    const sessions = await storageWithEncryption.getCollection('sessions');
    expect(sessions).toHaveLength(2);
    expect(sessions).toContain('session1');
    expect(sessions).toContain('session2');
  });

  test('It should encrypt collection data at rest', async () => {
    await storageWithEncryption.addToCollection('users', 'user1');

    // Access raw database to verify encryption
    const db = (storageWithEncryption as any).db;
    const rawValue = await db.get('mikroauth', 'coll:users');

    // Raw value should be encrypted
    expect(rawValue).not.toContain('user1');
    expect(rawValue).toContain(':'); // Encrypted format

    // But decrypted collection should be correct
    const decrypted = await storageWithEncryption.getCollection('users');
    expect(decrypted).toContain('user1');
  });

  test('It should handle encrypted collection removal', async () => {
    await storageWithEncryption.addToCollection('users', 'user1');
    await storageWithEncryption.addToCollection('users', 'user2');

    await storageWithEncryption.removeFromCollection('users', 'user1');

    const users = await storageWithEncryption.getCollection('users');
    expect(users).toHaveLength(1);
    expect(users).toContain('user2');
    expect(users).not.toContain('user1');
  });

  test('It should handle removing oldest from encrypted collection', async () => {
    await storageWithEncryption.addToCollection('tokens', 'token1');
    await storageWithEncryption.addToCollection('tokens', 'token2');

    const oldest =
      await storageWithEncryption.removeOldestFromCollection('tokens');
    expect(oldest).toBe('token1');

    const remaining = await storageWithEncryption.getCollection('tokens');
    expect(remaining).toHaveLength(1);
    expect(remaining).toContain('token2');
  });
});

describe('Search operations', () => {
  test('It should find keys matching a pattern', async () => {
    await storage.set('user:1:profile', 'data1');
    await storage.set('user:2:profile', 'data2');
    await storage.set('post:1:content', 'post1');

    const userKeys = await storage.findKeys('user:*:profile');
    expect(userKeys).toHaveLength(2);
    expect(userKeys).toContain('user:1:profile');
    expect(userKeys).toContain('user:2:profile');

    const specificUserKey = await storage.findKeys('user:1:*');
    expect(specificUserKey).toHaveLength(1);
    expect(specificUserKey).toContain('user:1:profile');
  });

  test('It should handle complex patterns', async () => {
    await storage.set('user:100:profile', 'data1');
    await storage.set('user:200:profile', 'data2');
    await storage.set('user:300:settings', 'settings3');

    const wildcard = await storage.findKeys('user:?00:*');
    expect(wildcard).toHaveLength(3);

    const specific = await storage.findKeys('user:*:profile');
    expect(specific).toHaveLength(2);
  });

  test('It should return empty array when no keys match', async () => {
    await storage.set('key1', 'value1');

    const results = await storage.findKeys('nomatch:*');
    expect(results).toEqual([]);
  });
});

describe('Integration with MikroAuth use cases', () => {
  test('It should handle magic link token storage and retrieval', async () => {
    const tokenKey = 'magic_link:abc123';
    const tokenData = JSON.stringify({
      email: 'user@example.com',
      createdAt: Date.now()
    });

    await storage.set(tokenKey, tokenData, 900);

    const retrievedData = await storage.get(tokenKey);
    expect(retrievedData).toBe(tokenData);
  });

  test('It should handle finding and invalidating existing magic links', async () => {
    await storage.set(
      'magic_link:token1',
      JSON.stringify({ email: 'user@example.com' })
    );
    await storage.set(
      'magic_link:token2',
      JSON.stringify({ email: 'user@example.com' })
    );
    await storage.set(
      'magic_link:token3',
      JSON.stringify({ email: 'other@example.com' })
    );

    const tokens = await storage.findKeys('magic_link:*');
    expect(tokens).toHaveLength(3);

    for (const key of tokens) {
      const data = await storage.get(key);
      if (data) {
        const parsed = JSON.parse(data);
        if (
          parsed.email === 'user@example.com' &&
          key !== 'magic_link:token2'
        ) {
          await storage.delete(key);
        }
      }
    }

    const remainingTokens = await storage.findKeys('magic_link:*');
    expect(remainingTokens).toHaveLength(2);
    expect(remainingTokens).toContain('magic_link:token2');
    expect(remainingTokens).toContain('magic_link:token3');
  });

  test('It should handle session tracking', async () => {
    const user = 'user@example.com';
    const sessionId1 = 'session123';
    const sessionId2 = 'session456';

    await storage.addToCollection(`sessions:${user}`, sessionId1);
    await storage.addToCollection(`sessions:${user}`, sessionId2);

    await storage.set(
      `refresh:${sessionId1}`,
      JSON.stringify({
        email: user,
        createdAt: Date.now(),
        tokenId: 'token123'
      })
    );

    const sessions = await storage.getCollection(`sessions:${user}`);
    expect(sessions).toHaveLength(2);
    expect(sessions).toContain(sessionId1);
    expect(sessions).toContain(sessionId2);

    await storage.removeFromCollection(`sessions:${user}`, sessionId1);
    await storage.delete(`refresh:${sessionId1}`);

    const updatedSessions = await storage.getCollection(`sessions:${user}`);
    expect(updatedSessions).toHaveLength(1);
    expect(updatedSessions).toContain(sessionId2);
    expect(updatedSessions).not.toContain(sessionId1);
    expect(await storage.get(`refresh:${sessionId1}`)).toBeNull();
  });

  test('It should handle encrypted session management', async () => {
    const user = 'sensitive@example.com';
    const sessionId = 'secure-session-123';
    const refreshTokenData = JSON.stringify({
      email: user,
      createdAt: Date.now(),
      metadata: { sensitive: 'data' }
    });

    await storageWithEncryption.addToCollection(`sessions:${user}`, sessionId);
    await storageWithEncryption.set(`refresh:${sessionId}`, refreshTokenData);

    // Verify data is encrypted at rest
    const db = (storageWithEncryption as any).db;
    const rawRefreshToken = await db.get(
      'mikroauth',
      `kv:refresh:${sessionId}`
    );
    expect(rawRefreshToken).not.toContain('sensitive@example.com');

    // But can be decrypted correctly
    const decrypted = await storageWithEncryption.get(`refresh:${sessionId}`);
    expect(decrypted).toBe(refreshTokenData);

    const sessions = await storageWithEncryption.getCollection(
      `sessions:${user}`
    );
    expect(sessions).toContain(sessionId);
  });
});

describe('Edge cases and error handling', () => {
  test('It should handle empty collections gracefully', async () => {
    const emptyCollection = await storage.getCollection('nonexistent');
    expect(emptyCollection).toEqual([]);
    expect(await storage.getCollectionSize('nonexistent')).toBe(0);
    expect(await storage.removeOldestFromCollection('nonexistent')).toBeNull();
  });

  test('It should handle removing from nonexistent collections', async () => {
    await expect(
      storage.removeFromCollection('nonexistent', 'item')
    ).resolves.not.toThrow();
  });

  test('It should maintain data integrity with mixed operations', async () => {
    await storage.set('key1', 'value1');
    await storage.addToCollection('collection1', 'item1');
    await storage.set('key2', 'value2');
    await storage.addToCollection('collection1', 'item2');

    expect(await storage.get('key1')).toBe('value1');
    expect(await storage.get('key2')).toBe('value2');

    const items = await storage.getCollection('collection1');
    expect(items).toHaveLength(2);
    expect(items).toContain('item1');
    expect(items).toContain('item2');
  });

  test('It should handle special characters in values', async () => {
    const specialValue = 'value with spaces & symbols: @#$%^&*()';
    await storage.set('special-key', specialValue);
    expect(await storage.get('special-key')).toBe(specialValue);
  });

  test('It should handle unicode characters', async () => {
    const unicodeValue = 'Hello 世界 🌍 مرحبا';
    await storage.set('unicode-key', unicodeValue);
    expect(await storage.get('unicode-key')).toBe(unicodeValue);
  });

  test('It should handle large values', async () => {
    const largeValue = 'x'.repeat(10000);
    await storage.set('large-key', largeValue);
    expect(await storage.get('large-key')).toBe(largeValue);
  });
});

describe('Encryption edge cases', () => {
  test('It should handle special characters in encrypted values', async () => {
    const specialValue = 'sensitive: @#$%^&*() with 世界 symbols';
    await storageWithEncryption.set('special', specialValue);
    expect(await storageWithEncryption.get('special')).toBe(specialValue);
  });

  test('It should handle empty strings', async () => {
    await storageWithEncryption.set('empty', '');
    expect(await storageWithEncryption.get('empty')).toBe('');
  });

  test('It should handle JSON-like strings', async () => {
    const jsonString = JSON.stringify({
      nested: { deeply: { value: 'test' } }
    });
    await storageWithEncryption.set('json', jsonString);
    expect(await storageWithEncryption.get('json')).toBe(jsonString);
  });
});
