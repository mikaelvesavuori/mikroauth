/**
 * @description Storage interface for MikroAuth.
 */
export interface StorageProvider {
  // Core key-value operations
  get(key: string): Promise<string | null>;
  set(key: string, value: string, expirySeconds?: number): Promise<void>;
  delete(key: string): Promise<void>;

  // Collection operations
  addToCollection(
    collectionKey: string,
    item: string,
    expirySeconds?: number
  ): Promise<void>;
  removeFromCollection(collectionKey: string, item: string): Promise<void>;
  getCollection(collectionKey: string): Promise<string[]>;
  getCollectionSize(collectionKey: string): Promise<number>;
  removeOldestFromCollection(collectionKey: string): Promise<string | null>;

  // Search operation
  findKeys(pattern: string): Promise<string[]>;
}

export interface DatabaseOperations {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<void>;
  list<T>(prefix: string): Promise<T[]>;
}

export interface EmailMessage {
  from: string;
  to: string | string[];
  cc?: string | string[];
  bcc?: string | string[];
  subject: string;
  text: string;
  html: string;
}

export interface EmailProvider {
  sendMail(message: EmailMessage): Promise<void>;
}

export interface JwtHeader {
  alg: string;
  typ: string;
}

export interface JwtClaims {
  // Standard claims
  iss?: string;
  sub?: string;
  aud?: string;
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;

  // Custom claims
  [key: string]: any;
}

export interface JwtSignOptions {
  exp?: number;
  notBefore?: number;
  issuer?: string;
  audience?: string;
  subject?: string;
  jwtid?: string;
}

export interface JwtVerifyOptions {
  issuer?: string;
  audience?: string;
  subject?: string;
  clockTolerance?: number;
}

export interface DecodedJwt {
  header: JwtHeader;
  payload: JwtClaims;
  signature: string;
}

export interface JwtPayload {
  sub: string; // Email
  jti: string; // Unique token ID
  iat?: number; // Issued at timestamp
  exp?: number; // Expiration timestamp
  lastLogin: number; // Unix timestamp of the last login
  metadata?: {
    ip?: string;
  };
}

export interface RequestContext {
  body?: Record<string, any>;
  query?: Record<string, any>;
  headers?: Record<string, any>;
  ip?: string;
  log?: {
    error: (message: string, error: Error) => void;
    info?: (message: string, ...args: any[]) => void;
  };
  user?: {
    email: string;
  };
}

export interface MagicLinkRequest {
  email: string;
  ip?: string;
}

export interface MagicLinkUrlParams {
  token: string;
  email: string;
}

export interface VerifyTokenRequest {
  token: string;
  email: string;
}

export interface SessionInfo {
  id: string;
  createdAt: number;
  lastLogin: number;
  lastUsed?: number;
  metadata?: {
    ip?: string;
  };
  isCurrentSession?: boolean;
}

export interface TokenResponse {
  accessToken: string;
  refreshToken: string;
  exp: number;
  tokenType: string;
}

export interface JwtPayload {
  sub: string;
  username?: string;
  email?: string;
  role?: string;
  jti: string; // Unique token ID
  iat?: number; // Issued at timestamp
  exp?: number; // Expiration timestamp
  lastLogin: number; // Unix timestamp of the last login
  metadata?: {
    ip?: string;
  };
}

export interface RequestContext {
  body?: Record<string, any>;
  query?: Record<string, any>;
  headers?: Record<string, any>;
  ip?: string;
  log?: {
    error: (message: string, error: Error) => void;
    info?: (message: string, ...args: any[]) => void;
  };
  user?: {
    email: string;
  };
}

export interface MagicLinkRequest {
  email: string;
  ip?: string;
}

export interface MagicLinkUrlParams {
  token: string;
  email: string;
}

export interface VerifyTokenRequest {
  token: string;
  email: string;
}

export interface SessionInfo {
  id: string;
  createdAt: number;
  lastLogin: number;
  lastUsed?: number;
  metadata?: {
    ip?: string;
  };
  isCurrentSession?: boolean;
}

export interface TokenResponse {
  accessToken: string;
  refreshToken: string;
  exp: number;
  tokenType: string;
}

export type UserIdentity = {
  id: string;
  email: string;
  username: string;
  role: string;
};

export type ConfigurationOptions = {
  config?: CombinedOptions;
  configFilePath?: string;
  args?: string[];
};

/**
 * @description Complete set of configurations for
 * authentication, the server, and any other providers.
 */
export type CombinedConfiguration = {
  auth: AuthConfiguration;
  email: EmailConfiguration;
  server: ServerConfiguration;
  storage: StorageConfiguration;
};

/**
 * @description The user-provided set of options for
 * authentication and the server.
 */
export type CombinedOptions = {
  auth: AuthOptions;
  email: EmailOptions;
  server: ServerOptions;
  storage: StorageOptions;
};

export type AuthConfiguration = {
  /**
   * The JSON Web Token secret to use.
   */
  jwtSecret: string;
  /**
   * How many seconds until a magic link expires?
   */
  magicLinkExpirySeconds: number;
  /**
   * How many seconds until the JSON Web Token expires?
   */
  jwtExpirySeconds: number;
  /**
   * How many seconds until the refresh token expires?
   */
  refreshTokenExpirySeconds: number;
  /**
   * How many sessions can be active?
   */
  maxActiveSessions: number;
  /**
   * The URL to the application we are authenticating towards.
   */
  appUrl: string;
  /**
   * Custom email templates.
   */
  templates: EmailTemplateConfiguration | null | undefined;
  /**
   * Use debug mode?
   */
  debug: boolean;
};

/**
 * @description Options for configuring MikroAuth.
 */
export type AuthOptions = Partial<AuthConfiguration>;

/**
 * @description Options to configure the server exposing MikroAuth.
 */
export type ServerConfiguration = {
  /**
   * Port to listen on (defaults to PORT env var or 3000)
   */
  port: number;
  /**
   * Host to bind to (defaults to HOST env var or '0.0.0.0')
   */
  host: string;
  /**
   * Whether to use HTTPS instead of HTTP
   */
  useHttps: boolean;
  /**
   * Whether to use HTTPS instead of HTTP
   */
  useHttp2: boolean;
  /**
   * Path to SSL certificate file (required if useHttps is true)
   */
  sslCert: string;
  /**
   * Path to SSL key file (required if useHttps is true)
   */
  sslKey: string;
  /**
   * Path to SSL CA certificate(s) file (optional)
   */
  sslCa: string;
  /**
   * Use debug mode?
   */
  debug: boolean;
};

/**
 * @description Options for configuring the server running MikroAuth.
 */
export type ServerOptions = Partial<ServerConfiguration>;

export type EmailConfiguration = {
  emailSubject: string;
  user: string;
  host: string;
  password: string;
  port: number;
  secure: boolean;
  maxRetries: number;
  debug: boolean;
  // Available in MikroMail but not supported here
  //timeout?: number;
  //clientName?: string;
  //retryDelay?: number;
  //skipAuthentication?: boolean; // Skip authentication step (for test servers)
};

export type EmailOptions = Partial<EmailConfiguration>;

export type StorageConfiguration = {
  databaseDirectory: string;
  encryptionKey: string;
  debug: boolean;
};

export type StorageOptions = Partial<StorageConfiguration>;

/**
 * @description Configuration for magic link email templates.
 * Defines the structure for text and HTML versions of authentication emails.
 */
export type EmailTemplateConfiguration = {
  textVersion: MagicLinkTemplate;
  htmlVersion: MagicLinkTemplate;
};

/**
 * @description Function that generates the text and HTML version of the email.
 * @param magicLink - The authentication link to include in the email.
 * @param expiryMinutes - The number of minutes until the link expires.
 * @returns The formatted text or HTML content for the email.
 */
export type MagicLinkTemplate = (
  magicLink: string,
  expiryMinutes: number
) => string;
