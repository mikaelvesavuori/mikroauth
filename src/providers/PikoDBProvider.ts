import type { PikoDB } from 'pikodb';

import type { StorageProvider } from '../interfaces/index.js';
import { Encryption } from '../utils/encryption.js';

/**
 * @description PikoDB implementation of the StorageProvider interface.
 * Provides lightweight, reliable key-value storage with optional encryption.
 */
export class PikoDBProvider implements StorageProvider {
  private readonly db: PikoDB;
  private readonly encryption?: Encryption;
  private readonly PREFIX_KV = 'kv:';
  private readonly PREFIX_COLLECTION = 'coll:';
  private readonly TABLE_NAME = 'mikroauth';

  constructor(pikoDB: PikoDB, encryptionKey?: string) {
    this.db = pikoDB;
    if (encryptionKey) {
      this.encryption = new Encryption(encryptionKey);
    }
  }

  /**
   * @description Start the PikoDB instance.
   */
  public async start() {
    await this.db.start();
  }

  /**
   * @description Close the database connection and clean up resources.
   */
  public async close(): Promise<void> {
    await this.db.close();
  }

  /**
   * @description Set a value with optional expiry.
   */
  async set(key: string, value: string, expirySeconds?: number): Promise<void> {
    const dbKey = `${this.PREFIX_KV}${key}`;
    const storedValue = this.encryption
      ? this.encryption.encrypt(value)
      : value;
    const expiration = expirySeconds
      ? Date.now() + expirySeconds * 1000
      : undefined;

    await this.db.write(this.TABLE_NAME, dbKey, storedValue, expiration);
  }

  /**
   * @description Get a value by key.
   */
  async get(key: string): Promise<string | null> {
    const dbKey = `${this.PREFIX_KV}${key}`;

    const result = await this.db.get(this.TABLE_NAME, dbKey);

    if (!result) return null;

    return this.encryption ? this.encryption.decrypt(result) : result;
  }

  /**
   * @description Delete a key.
   */
  async delete(key: string): Promise<void> {
    const dbKey = `${this.PREFIX_KV}${key}`;
    await this.db.delete(this.TABLE_NAME, dbKey);
  }

  /**
   * @description Add an item to a collection.
   */
  async addToCollection(
    collectionKey: string,
    item: string,
    expirySeconds?: number
  ): Promise<void> {
    const dbKey = `${this.PREFIX_COLLECTION}${collectionKey}`;

    const existingCollection = await this.db.get(this.TABLE_NAME, dbKey);

    let collection: string[] = [];
    if (existingCollection) {
      const decrypted = this.encryption
        ? this.encryption.decrypt(existingCollection)
        : existingCollection;
      collection = JSON.parse(decrypted);
    }

    if (!collection.includes(item)) collection.push(item);

    const serialized = JSON.stringify(collection);
    const storedValue = this.encryption
      ? this.encryption.encrypt(serialized)
      : serialized;
    const expiration = expirySeconds
      ? Date.now() + expirySeconds * 1000
      : undefined;

    await this.db.write(this.TABLE_NAME, dbKey, storedValue, expiration);
  }

  /**
   * @description Remove an item from a collection.
   */
  async removeFromCollection(
    collectionKey: string,
    item: string
  ): Promise<void> {
    const dbKey = `${this.PREFIX_COLLECTION}${collectionKey}`;

    const existingCollection = await this.db.get(this.TABLE_NAME, dbKey);

    if (!existingCollection) return;

    const decrypted = this.encryption
      ? this.encryption.decrypt(existingCollection)
      : existingCollection;
    let collection = JSON.parse(decrypted);
    collection = collection.filter((i: string) => i !== item);

    const serialized = JSON.stringify(collection);
    const storedValue = this.encryption
      ? this.encryption.encrypt(serialized)
      : serialized;

    await this.db.write(this.TABLE_NAME, dbKey, storedValue);
  }

  /**
   * @description Get all items in a collection.
   */
  async getCollection(collectionKey: string): Promise<string[]> {
    const dbKey = `${this.PREFIX_COLLECTION}${collectionKey}`;

    const result = await this.db.get(this.TABLE_NAME, dbKey);

    if (!result) return [];

    const decrypted = this.encryption
      ? this.encryption.decrypt(result)
      : result;
    const collection = JSON.parse(decrypted);

    return collection;
  }

  /**
   * @description Get the number of items in a collection.
   */
  async getCollectionSize(collectionKey: string): Promise<number> {
    const items = await this.getCollection(collectionKey);
    return items.length;
  }

  /**
   * @description Remove and return the oldest item from a collection.
   */
  async removeOldestFromCollection(
    collectionKey: string
  ): Promise<string | null> {
    const dbKey = `${this.PREFIX_COLLECTION}${collectionKey}`;

    // Get existing collection
    const existingCollection = await this.db.get(this.TABLE_NAME, dbKey);

    if (!existingCollection) return null;

    // Parse collection
    const decrypted = this.encryption
      ? this.encryption.decrypt(existingCollection)
      : existingCollection;
    const collection = JSON.parse(decrypted);
    if (collection.length === 0) return null;

    // Remove the oldest item (first in the array)
    const oldest = collection.shift();

    // Write back the modified collection
    const serialized = JSON.stringify(collection);
    const storedValue = this.encryption
      ? this.encryption.encrypt(serialized)
      : serialized;

    await this.db.write(this.TABLE_NAME, dbKey, storedValue);

    return oldest;
  }

  /**
   * @description Find keys matching a pattern.
   * Supports wildcards: * (any characters) and ? (single character).
   */
  async findKeys(pattern: string): Promise<string[]> {
    // Convert wildcard pattern to regex pattern
    const regexPattern = pattern
      .replace(/\./g, '\\.') // Escape dots
      .replace(/\*/g, '.*') // Convert * to .*
      .replace(/\?/g, '.'); // Convert ? to .

    const regex = new RegExp(`^${regexPattern}$`);

    // Get all entries from the table
    const results = await this.db.get(this.TABLE_NAME);

    // PikoDB returns an array of [key, value] tuples when no key is specified
    if (!Array.isArray(results)) return [];

    // Filter and transform keys
    return results
      .filter((entry: any) => {
        const key = entry[0]; // The key is at index 0
        return typeof key === 'string' && key.startsWith(this.PREFIX_KV);
      })
      .map((entry: any) => entry[0].substring(this.PREFIX_KV.length)) // Extract key part after prefix
      .filter((key: string) => regex.test(key)); // Apply the regex pattern
  }
}
