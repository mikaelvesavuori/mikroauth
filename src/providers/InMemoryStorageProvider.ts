import { EventEmitter } from 'node:events';

import type { StorageProvider } from '../interfaces/index.js';

/**
 * @description In-memory implementation of the StorageProvider interface.
 */
export class InMemoryStorageProvider implements StorageProvider {
  private data: Map<string, { value: string; expiry: number | null }> =
    new Map();
  private collections: Map<string, { items: string[]; expiry: number | null }> =
    new Map();
  private expiryEmitter = new EventEmitter();
  private expiryCheckInterval: NodeJS.Timeout;

  constructor(checkIntervalMs = 1000) {
    // Check for expired items periodically
    this.expiryCheckInterval = setInterval(
      () => this.checkExpiredItems(),
      checkIntervalMs
    );
  }

  /**
   * @description Clean up resources.
   */
  public destroy(): void {
    clearInterval(this.expiryCheckInterval);
    this.data.clear();
    this.collections.clear();
    this.expiryEmitter.removeAllListeners();
  }

  /**
   * @description Check for and remove expired items.
   */
  private checkExpiredItems(): void {
    const now = Date.now();

    // Check regular key-value data
    for (const [key, item] of this.data.entries()) {
      if (item.expiry && item.expiry < now) {
        this.data.delete(key);
        this.expiryEmitter.emit('expired', key);
      }
    }

    // Check collections
    for (const [key, collection] of this.collections.entries()) {
      if (collection.expiry && collection.expiry < now) {
        this.collections.delete(key);
        this.expiryEmitter.emit('expired', key);
      }
    }
  }

  /**
   * @description Set a value with optional expiry.
   */
  async set(key: string, value: string, expirySeconds?: number): Promise<void> {
    const expiry = expirySeconds ? Date.now() + expirySeconds * 1000 : null;
    this.data.set(key, { value, expiry });
  }

  /**
   * @description Get a value by key.
   */
  async get(key: string): Promise<string | null> {
    const item = this.data.get(key);
    if (!item) return null;

    // Check if expired
    if (item.expiry && item.expiry < Date.now()) {
      this.data.delete(key);
      return null;
    }

    return item.value;
  }

  /**
   * @description Delete a key.
   */
  async delete(key: string): Promise<void> {
    this.data.delete(key);
    this.collections.delete(key);
  }

  /**
   * @description Add an item to a collection.
   */
  async addToCollection(
    collectionKey: string,
    item: string,
    expirySeconds?: number
  ): Promise<void> {
    if (!this.collections.has(collectionKey)) {
      this.collections.set(collectionKey, {
        items: [],
        expiry: expirySeconds ? Date.now() + expirySeconds * 1000 : null
      });
    }

    const collection = this.collections.get(collectionKey)!;

    if (expirySeconds) collection.expiry = Date.now() + expirySeconds * 1000;

    collection.items.push(item);
  }

  /**
   * @description Remove an item from a collection.
   */
  async removeFromCollection(
    collectionKey: string,
    item: string
  ): Promise<void> {
    const collection = this.collections.get(collectionKey);
    if (!collection) return;

    collection.items = collection.items.filter((i) => i !== item);
  }

  /**
   * @description Get all items in a collection.
   */
  async getCollection(collectionKey: string): Promise<string[]> {
    const collection = this.collections.get(collectionKey);

    return collection ? [...collection.items] : [];
  }

  /**
   * @description Get the number of items in a collection.
   */
  async getCollectionSize(collectionKey: string): Promise<number> {
    const collection = this.collections.get(collectionKey);

    return collection ? collection.items.length : 0;
  }

  /**
   * @description Remove and return the oldest item from a collection.
   */
  async removeOldestFromCollection(
    collectionKey: string
  ): Promise<string | null> {
    const collection = this.collections.get(collectionKey);
    if (!collection || collection.items.length === 0) return null;

    return collection.items.shift() || null;
  }

  /**
   * @description Find keys matching a pattern (simple wildcard support).
   */
  async findKeys(pattern: string): Promise<string[]> {
    const regexPattern = pattern
      .replace(/\*/g, '.*') // Convert * to .*
      .replace(/\?/g, '.'); // Convert ? to .

    const regex = new RegExp(`^${regexPattern}$`);

    const dataKeys = Array.from(this.data.keys()).filter((key) =>
      regex.test(key)
    );

    const collectionKeys = Array.from(this.collections.keys()).filter((key) =>
      regex.test(key)
    );

    return [...new Set([...dataKeys, ...collectionKeys])];
  }
}
