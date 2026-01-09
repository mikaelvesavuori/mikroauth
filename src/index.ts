export type {
  CreateTokenRequest,
  EmailProvider,
  StorageProvider
} from './interfaces/index.js';

export { MikroAuth } from './MikroAuth.js';

export { PikoDBProvider } from './providers/PikoDBProvider.js';
export { MikroMailProvider } from './providers/MikroMailProvider.js';
export { InMemoryEmailProvider } from './providers/InMemoryEmailProvider.js';
export { InMemoryStorageProvider } from './providers/InMemoryStorageProvider.js';

// API-based email providers
export { ResendProvider } from './providers/ResendProvider.js';
export { BrevoProvider } from './providers/BrevoProvider.js';
export { PostmarkProvider } from './providers/PostmarkProvider.js';
export { SendGridProvider } from './providers/SendGridProvider.js';
export { AWSESProvider } from './providers/AWSESProvider.js';
