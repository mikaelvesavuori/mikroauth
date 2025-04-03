import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import { InMemoryStorageProvider } from '../../src/providers/InMemoryStorageProvider.js';

let storage: InMemoryStorageProvider;

beforeEach(() => (storage = new InMemoryStorageProvider()));

afterEach(() => {
  storage.destroy();
  vi.restoreAllMocks();
});

describe('Key-value operations', () => {
  test('It should set and get values', async () => {
    await storage.set('key1', 'value1');
    expect(await storage.get('key1')).toBe('value1');

    // Non-existent key should return null
    expect(await storage.get('non-existent')).toBeNull();
  });

  test('It should delete values', async () => {
    await storage.set('key1', 'value1');
    await storage.delete('key1');
    expect(await storage.get('key1')).toBeNull();
  });

  test('It should handle value expiration', async () => {
    await storage.set('expiring-key', 'value', 1); // 1 second expiry

    expect(await storage.get('expiring-key')).toBe('value');

    await new Promise((resolve) => setTimeout(resolve, 1100));

    expect(await storage.get('expiring-key')).toBeNull();
  });
});

describe('Collection operations', () => {
  test('It should handle collection expiration', async () => {
    await storage.addToCollection('expiring-collection', 'item1', 0.5);

    expect(await storage.getCollectionSize('expiring-collection')).toBe(1);

    await new Promise((resolve) => setTimeout(resolve, 1100));

    expect(await storage.getCollectionSize('expiring-collection')).toBe(0);
  });

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
    await storage.addToCollection('users', 'user2');

    const oldest = await storage.removeOldestFromCollection('users');
    expect(oldest).toBe('user1');

    const users = await storage.getCollection('users');
    expect(users).toHaveLength(1);
    expect(users).toContain('user2');
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

  test('It should find collection keys matching a pattern', async () => {
    await storage.addToCollection('sessions:user1', 'session1');
    await storage.addToCollection('sessions:user2', 'session2');
    await storage.set('user:profile', 'data');

    const sessionKeys = await storage.findKeys('sessions:*');
    expect(sessionKeys).toHaveLength(2);
    expect(sessionKeys).toContain('sessions:user1');
    expect(sessionKeys).toContain('sessions:user2');
  });
});

describe('Integration with MikroAuth use cases', () => {
  test('It should handle magic link token storage and retrieval', async () => {
    const tokenKey = 'magic_link:abc123';
    const tokenData = JSON.stringify({
      email: 'user@example.com',
      createdAt: Date.now()
    });

    await storage.set(tokenKey, tokenData, 900); // 15 minutes

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
});
