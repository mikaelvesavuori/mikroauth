import type { MikroDB } from 'mikrodb';

import type { StorageProvider } from '../interfaces/index.js';

/**
 * @description MikroDB implementation of the StorageProvider interface.
 */
export class MikroDBProvider implements StorageProvider {
  private readonly db: MikroDB;
  private readonly PREFIX_KV = 'kv:';
  private readonly PREFIX_COLLECTION = 'coll:';
  private readonly TABLE_NAME = 'mikroauth';

  constructor(mikroDb: MikroDB) {
    this.db = mikroDb;
  }

  /**
   * @description Start the MikroDB instance.
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
    const expiration = expirySeconds
      ? Date.now() + expirySeconds * 1000
      : undefined;

    await this.db.write({
      tableName: this.TABLE_NAME,
      key: dbKey,
      value,
      expiration
    });
  }

  /**
   * @description Get a value by key.
   */
  async get(key: string): Promise<string | null> {
    const dbKey = `${this.PREFIX_KV}${key}`;

    const result = await this.db.get({
      tableName: this.TABLE_NAME,
      key: dbKey
    });

    if (!result) return null;
    return result;
  }

  /**
   * @description Delete a key.
   */
  async delete(key: string): Promise<void> {
    const dbKey = `${this.PREFIX_KV}${key}`;

    await this.db.delete({
      tableName: this.TABLE_NAME,
      key: dbKey
    });
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

    const existingCollection = await this.db.get({
      tableName: this.TABLE_NAME,
      key: dbKey
    });

    let collection: string[] = [];
    if (existingCollection) collection = JSON.parse(existingCollection);
    if (!collection.includes(item)) collection.push(item);

    const expiration = expirySeconds
      ? Date.now() + expirySeconds * 1000
      : undefined;

    await this.db.write({
      tableName: this.TABLE_NAME,
      key: dbKey,
      value: JSON.stringify(collection),
      expiration
    });
  }

  /**
   * @description Remove an item from a collection.
   */
  async removeFromCollection(
    collectionKey: string,
    item: string
  ): Promise<void> {
    const dbKey = `${this.PREFIX_COLLECTION}${collectionKey}`;

    const existingCollection = await this.db.get({
      tableName: this.TABLE_NAME,
      key: dbKey
    });

    if (!existingCollection) return;

    let collection = JSON.parse(existingCollection);
    collection = collection.filter((i: string) => i !== item);

    await this.db.write({
      tableName: this.TABLE_NAME,
      key: dbKey,
      value: JSON.stringify(collection)
    });
  }

  /**
   * @description Get all items in a collection.
   */
  async getCollection(collectionKey: string): Promise<string[]> {
    const dbKey = `${this.PREFIX_COLLECTION}${collectionKey}`;

    const result = await this.db.get({
      tableName: this.TABLE_NAME,
      key: dbKey
    });

    if (!result) return [];

    const collection = JSON.parse(result);

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
    const existingCollection = await this.db.get({
      tableName: this.TABLE_NAME,
      key: dbKey
    });

    if (!existingCollection) return null;

    // Parse collection
    const collection = JSON.parse(existingCollection);
    if (collection.length === 0) return null;

    // Remove the oldest item (first in the array)
    const oldest = collection.shift();

    // Write back the modified collection
    await this.db.write({
      tableName: this.TABLE_NAME,
      key: dbKey,
      value: JSON.stringify(collection)
    });

    return oldest;
  }

  /**
   * @description Find keys matching a pattern.
   */
  async findKeys(pattern: string): Promise<string[]> {
    // Convert wildcard pattern to regex pattern
    const regexPattern = pattern
      .replace(/\./g, '\\.') // Escape dots
      .replace(/\*/g, '.*') // Convert * to .*
      .replace(/\?/g, '.'); // Convert ? to .

    const regex = new RegExp(`^${regexPattern}$`);

    // Get all KV keys
    const results = await this.db.get({
      tableName: this.TABLE_NAME
    });

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
