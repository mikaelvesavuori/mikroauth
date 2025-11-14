import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import type {
  MagicLinkRequest,
  VerifyTokenRequest
} from '../src/interfaces/index.js';

import { JsonWebToken } from '../src/JsonWebToken.js';
import { MikroAuth } from '../src/MikroAuth.js';

import { InMemoryEmailProvider } from '../src/providers/InMemoryEmailProvider.js';
import { InMemoryStorageProvider } from '../src/providers/InMemoryStorageProvider.js';

const TEST_JWT_SECRET = 'test-jwt-secret-key-for-mikroauth-tests';
const TEST_APP_URL = 'http://test-app.com';
const TEST_EMAIL = 'test@example.com';
const TEST_MAGIC_LINK_EXPIRY = 900; // 15 minutes
const TEST_JWT_EXPIRY = 3600; // 1 hour
const TEST_REFRESH_EXPIRY = 2592000; // 30 days

let storageProvider: InMemoryStorageProvider;
let emailProvider: InMemoryEmailProvider;
let auth: MikroAuth;

beforeEach(() => {
  storageProvider = new InMemoryStorageProvider();
  emailProvider = new InMemoryEmailProvider();

  auth = new MikroAuth(
    {
      auth: {
        jwtSecret: TEST_JWT_SECRET,
        appUrl: TEST_APP_URL,
        magicLinkExpirySeconds: TEST_MAGIC_LINK_EXPIRY,
        jwtExpirySeconds: TEST_JWT_EXPIRY,
        refreshTokenExpirySeconds: TEST_REFRESH_EXPIRY,
        maxActiveSessions: 3,
        templates: null,
        debug: false
      }
    } as any,
    emailProvider,
    storageProvider
  );
});

afterEach(() => vi.restoreAllMocks());

describe('Initialization', () => {
  test('It should create a valid instance with proper configuration', () => {
    expect(auth).toBeInstanceOf(MikroAuth);
  });

  test('It should warn when using default secrets in production', () => {
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';

    // @ts-expect-error
    expect(() => new MikroAuth(storage, emailProvider, {})).toThrowError();

    process.env.NODE_ENV = originalEnv;
  });
});

describe('Email validation', () => {
  const invalidEmails = [
    // Missing @ symbol
    'invalidemail.com',
    'user.example.com',
    'userexample.com',

    // Missing domain
    'user@',
    'user@.',

    // Missing username
    '@example.com',

    // Invalid characters
    'user name@example.com',
    'user<>@example.com',
    'user()@example.com',
    'user[]@example.com',
    'user\\@example.com',
    'user"@example.com',

    // Multiple @ symbols
    'user@domain@example.com',

    // Invalid TLD format
    'user@domain.c',
    'user@domain.',

    // IP addresses without brackets
    'user@127.0.0.1',

    // Excessively long parts
    `${'a'.repeat(65)}@example.com`, // Local part > 64 chars
    `user@${'a'.repeat(65)}.com`, // Domain part too long

    // Invalid dot placement
    '.user@example.com',
    'user.@example.com',
    'user@.example.com',
    'user@example..com',

    // Empty parts between dots
    'user@example..com',
    'user..name@example.com',

    // Unicode/emoji in incorrect positions (might be valid in some contexts but commonly rejected)
    'user@😊.com',
    '😊@example.com'
  ];

  const validEmails = [
    'simple@example.com',
    'very.common@example.com',
    'disposable.style.email.with+symbol@example.com',
    'other.email-with-hyphen@example.com',
    'fully-qualified-domain@example.com',
    'user.name+tag+sorting@example.com',
    'x@example.com',
    'example-indeed@strange-example.com',
    'example@s.example',
    'mailhost!username@example.org',
    'user%example.com@example.org',
    'user@[IPv6:2001:db8:1ff::a0b:dbd0]',
    'user@[192.168.2.1]'
  ];

  test('It should reject invalid email addresses', async () => {
    for (const email of invalidEmails) {
      const request = {
        email,
        ip: '192.168.1.1'
      };

      await expect(auth.createMagicLink(request)).rejects.toThrow(
        'Valid email required'
      );
    }
  });

  test('It should accept valid email addresses', async () => {
    for (const email of validEmails) {
      const request = {
        email,
        ip: '192.168.1.1'
      };

      try {
        await auth.createMagicLink(request);
      } catch (error: any) {
        if (error.message.includes('Valid email required'))
          throw new Error(`Valid email '${email}' was incorrectly rejected`);
      }
    }
  });
});

describe('Magic link generation', () => {
  test('It should generate and send magic link email', async () => {
    const request: MagicLinkRequest = {
      email: TEST_EMAIL,
      ip: '192.168.1.1'
    };

    const result = await auth.createMagicLink(request);

    expect(result.message).toBe(
      'If a matching account was found, a magic link has been sent.'
    );

    const emails = emailProvider.getSentEmails();
    expect(emails).toHaveLength(1);
    expect(emails[0].to).toBe(TEST_EMAIL);
    expect(emails[0].subject).toBe('Your Secure Login Link');

    expect(emails[0].text).toContain(TEST_APP_URL);
    expect(emails[0].text).toContain('?token=');
    expect(emails[0].text).toContain(
      `&email=${encodeURIComponent(TEST_EMAIL)}`
    );

    const keys = await storageProvider.findKeys('magic_link:*');
    expect(keys).toHaveLength(1);

    const tokenData = await storageProvider.get(keys[0]);
    expect(tokenData).not.toBeNull();

    const metadata = JSON.parse(tokenData ?? '{}');
    expect(metadata.email).toBe(TEST_EMAIL);
    expect(metadata.ipAddress).toBe(request.ip);
  });

  test('It should invalidate previous magic links for the same email', async () => {
    await auth.createMagicLink({
      email: TEST_EMAIL,
      ip: '192.168.1.1'
    });

    const firstTokenKeys = await storageProvider.findKeys('magic_link:*');
    expect(firstTokenKeys).toHaveLength(1);

    await auth.createMagicLink({
      email: TEST_EMAIL,
      ip: '192.168.1.2'
    });

    const allTokenKeys = await storageProvider.findKeys('magic_link:*');
    expect(allTokenKeys).toHaveLength(1);

    const firstTokenData = await storageProvider.get(firstTokenKeys[0]);
    expect(firstTokenData).toBeNull();
  });

  test('It should handle API request context for magicLink method', async () => {
    const requestContext = {
      email: TEST_EMAIL,
      ip: '192.168.1.1',
      headers: { 'user-agent': 'Test Browser' }
    };

    const result = await auth.createMagicLink(requestContext);

    expect(result.message).toBe(
      'If a matching account was found, a magic link has been sent.'
    );

    const emails = emailProvider.getSentEmails();
    expect(emails).toHaveLength(1);
    expect(emails[0].to).toBe(TEST_EMAIL);
  });

  test('It should throw error for missing email in request context', async () => {
    const requestContext = {
      email: 'z',
      ip: '192.168.1.1',
      headers: { 'user-agent': 'Test Browser' }
    };

    await expect(auth.createMagicLink(requestContext)).rejects.toThrow();
  });
});

describe('Token verification', () => {
  test('It should verify token and create session', async () => {
    await auth.createMagicLink({
      email: TEST_EMAIL,
      ip: '192.168.1.1'
    });

    const tokenKeys = await storageProvider.findKeys('magic_link:*');
    const tokenKey = tokenKeys[0];
    const token = tokenKey.replace('magic_link:', '');

    const result = await auth.verifyToken({
      token,
      email: TEST_EMAIL
    });

    expect(result).toHaveProperty('accessToken');
    expect(result).toHaveProperty('refreshToken');
    expect(result).toHaveProperty('exp', TEST_JWT_EXPIRY);
    expect(result).toHaveProperty('tokenType', 'Bearer');

    const jwtService = new JsonWebToken(TEST_JWT_SECRET);
    const decoded = jwtService.verify(result.accessToken);

    expect(decoded.sub).toBe(TEST_EMAIL);
    expect(decoded).toHaveProperty('jti');

    const magicLinkData = await storageProvider.get(tokenKey);
    expect(magicLinkData).toBeNull();

    const sessions = await storageProvider.getCollection(
      `sessions:${TEST_EMAIL}`
    );
    expect(sessions).toHaveLength(1);
    expect(sessions[0]).toBe(result.refreshToken);

    const refreshData = await storageProvider.get(
      `refresh:${result.refreshToken}`
    );
    expect(refreshData).not.toBeNull();

    const refreshMetadata = JSON.parse(refreshData ?? '{}');
    expect(refreshMetadata.email).toBe(TEST_EMAIL);
  });

  test('It should reject verification with invalid token', async () => {
    const params: VerifyTokenRequest = {
      token: 'invalid-token',
      email: TEST_EMAIL
    };

    await expect(auth.verifyToken(params)).rejects.toThrow(
      'Verification failed'
    );
  });

  test('It should reject verification with email mismatch', async () => {
    await auth.createMagicLink({
      email: TEST_EMAIL,
      ip: '192.168.1.1'
    });

    const tokenKeys = await storageProvider.findKeys('magic_link:*');
    const token = tokenKeys[0].replace('magic_link:', '');

    const params: VerifyTokenRequest = {
      token,
      email: 'wrong@example.com'
    };

    await expect(auth.verifyToken(params)).rejects.toThrow(
      'Verification failed'
    );
  });

  test('It should handle API request context for verify method', async () => {
    await auth.createMagicLink({
      email: TEST_EMAIL,
      ip: '192.168.1.1'
    });

    const tokenKeys = await storageProvider.findKeys('magic_link:*');
    const token = tokenKeys[0].replace('magic_link:', '');

    const requestContext = {
      token,
      email: TEST_EMAIL
    };

    const result = await auth.verifyToken(requestContext);

    expect(result).toHaveProperty('accessToken');
    expect(result).toHaveProperty('refreshToken');
  });
});

describe('Token refresh', () => {
  test('It should refresh access token with valid refresh token', async () => {
    await auth.createMagicLink({
      email: TEST_EMAIL,
      ip: '192.168.1.1'
    });

    const tokenKeys = await storageProvider.findKeys('magic_link:*');
    const token = tokenKeys[0].replace('magic_link:', '');

    const verifyResult = await auth.verifyToken({
      token,
      email: TEST_EMAIL
    });

    const refreshToken = verifyResult.refreshToken;

    const refreshResult = await auth.refreshAccessToken(refreshToken);

    expect(refreshResult).toHaveProperty('accessToken');
    expect(refreshResult).toHaveProperty('refreshToken', refreshToken); // Same refresh token
    expect(refreshResult).toHaveProperty('exp', TEST_JWT_EXPIRY);
    expect(refreshResult).toHaveProperty('tokenType', 'Bearer');

    const jwtService = new JsonWebToken(TEST_JWT_SECRET);
    const decoded = jwtService.verify(refreshResult.accessToken);

    expect(decoded.sub).toBe(TEST_EMAIL);

    const refreshData = await storageProvider.get(`refresh:${refreshToken}`);
    const refreshMetadata = JSON.parse(refreshData ?? '{}');
    expect(refreshMetadata).toHaveProperty('lastUsed');
  });

  test('It should reject refresh with invalid refresh token', async () => {
    await expect(
      auth.refreshAccessToken('invalid-refresh-token')
    ).rejects.toThrow('Token refresh failed');
  });

  test('It should handle API request context for refresh method', async () => {
    await auth.createMagicLink({
      email: TEST_EMAIL,
      ip: '192.168.1.1'
    });

    const tokenKeys = await storageProvider.findKeys('magic_link:*');
    const token = tokenKeys[0].replace('magic_link:', '');

    const verifyResult = await auth.verifyToken({
      token,
      email: TEST_EMAIL
    });

    const refreshToken = verifyResult.refreshToken;

    const refreshResult = await auth.refreshAccessToken(refreshToken);

    expect(refreshResult).toHaveProperty('accessToken');
  });
});

describe('Session management', () => {
  test('It should track sessions up to the maximum limit', async () => {
    await auth.createMagicLink({ email: TEST_EMAIL });
    let tokenKeys = await storageProvider.findKeys('magic_link:*');
    let token = tokenKeys[0].replace('magic_link:', '');

    const result1 = await auth.verifyToken({ token, email: TEST_EMAIL });

    await auth.createMagicLink({ email: TEST_EMAIL });
    tokenKeys = await storageProvider.findKeys('magic_link:*');
    token = tokenKeys[0].replace('magic_link:', '');

    const result2 = await auth.verifyToken({ token, email: TEST_EMAIL });

    await auth.createMagicLink({ email: TEST_EMAIL });
    tokenKeys = await storageProvider.findKeys('magic_link:*');
    token = tokenKeys[0].replace('magic_link:', '');

    const result3 = await auth.verifyToken({ token, email: TEST_EMAIL });

    await auth.createMagicLink({ email: TEST_EMAIL });
    tokenKeys = await storageProvider.findKeys('magic_link:*');
    token = tokenKeys[0].replace('magic_link:', '');

    const result4 = await auth.verifyToken({ token, email: TEST_EMAIL });

    const sessions = await storageProvider.getCollection(
      `sessions:${TEST_EMAIL}`
    );
    expect(sessions).toHaveLength(3);

    expect(sessions).not.toContain(result1.refreshToken);

    expect(sessions).toContain(result2.refreshToken);
    expect(sessions).toContain(result3.refreshToken);
    expect(sessions).toContain(result4.refreshToken);
  });

  test('It should get all active sessions', async () => {
    await auth.createMagicLink({ email: TEST_EMAIL });
    const tokenKeys = await storageProvider.findKeys('magic_link:*');
    const token = tokenKeys[0].replace('magic_link:', '');

    const { refreshToken } = await auth.verifyToken({
      token,
      email: TEST_EMAIL
    });

    const requestContext = {
      user: { email: TEST_EMAIL },
      body: { refreshToken }
    };

    const result = await auth.getSessions(requestContext);

    expect(result).toHaveProperty('sessions');
    expect(result.sessions).toHaveLength(1);
    expect(result.sessions[0]).toHaveProperty('isCurrentSession', true);
    expect(result.sessions[0]).toHaveProperty('id');
    expect(result.sessions[0]).toHaveProperty('createdAt');
    expect(result.sessions[0]).toHaveProperty('lastLogin');
    expect(result.sessions[0]).toHaveProperty('metadata');
  });

  test('It should logout and remove session', async () => {
    await auth.createMagicLink({ email: TEST_EMAIL });
    const tokenKeys = await storageProvider.findKeys('magic_link:*');
    const token = tokenKeys[0].replace('magic_link:', '');

    const { refreshToken } = await auth.verifyToken({
      token,
      email: TEST_EMAIL
    });

    const result = await auth.logout(refreshToken);

    expect(result).toHaveProperty('message', 'Logged out successfully.');

    const sessions = await storageProvider.getCollection(
      `sessions:${TEST_EMAIL}`
    );
    expect(sessions).not.toContain(refreshToken);

    const refreshData = await storageProvider.get(`refresh:${refreshToken}`);
    expect(refreshData).toBeNull();
  });

  test('It should revoke all sessions', async () => {
    for (let i = 0; i < 3; i++) {
      await auth.createMagicLink({ email: TEST_EMAIL });
      const tokenKeys = await storageProvider.findKeys('magic_link:*');
      const token = tokenKeys[0].replace('magic_link:', '');
      await auth.verifyToken({ token, email: TEST_EMAIL });
    }

    let sessions = await storageProvider.getCollection(
      `sessions:${TEST_EMAIL}`
    );
    expect(sessions).toHaveLength(3);

    const requestContext = {
      user: { email: TEST_EMAIL }
    };

    const result = await auth.revokeSessions(requestContext);

    expect(result).toHaveProperty(
      'message',
      'All other sessions revoked successfully.'
    );

    sessions = await storageProvider.getCollection(`sessions:${TEST_EMAIL}`);
    expect(sessions).toHaveLength(0);
  });

  test('It should revoke all sessions except the current session', async () => {
    let currentRefreshToken: any;

    for (let i = 0; i < 3; i++) {
      await auth.createMagicLink({ email: TEST_EMAIL });
      const tokenKeys = await storageProvider.findKeys('magic_link:*');
      const token = tokenKeys[0].replace('magic_link:', '');
      const result = await auth.verifyToken({ token, email: TEST_EMAIL });

      if (i === 1) {
        currentRefreshToken = result.refreshToken;
      }
    }

    let sessions = await storageProvider.getCollection(
      `sessions:${TEST_EMAIL}`
    );
    expect(sessions).toHaveLength(3);

    const requestContext = {
      user: { email: TEST_EMAIL },
      body: { refreshToken: currentRefreshToken }
    };

    const result = await auth.revokeSessions(requestContext);

    expect(result).toHaveProperty(
      'message',
      'All other sessions revoked successfully.'
    );

    sessions = await storageProvider.getCollection(`sessions:${TEST_EMAIL}`);
    expect(sessions).toHaveLength(1);
    expect(sessions[0]).toBe(currentRefreshToken);
  });
});

describe('JWT authentication', () => {
  test('It should verify JWT token correctly', async () => {
    await auth.createMagicLink({ email: TEST_EMAIL });
    const tokenKeys = await storageProvider.findKeys('magic_link:*');
    const token = tokenKeys[0].replace('magic_link:', '');

    const { accessToken } = await auth.verifyToken({
      token,
      email: TEST_EMAIL
    });

    const payload = auth.verify(accessToken);

    expect(payload).toHaveProperty('sub', TEST_EMAIL);
    expect(payload).toHaveProperty('jti');
    expect(payload).toHaveProperty('lastLogin');
    expect(payload).toHaveProperty('metadata');
  });

  test('It should reject invalid JWT token', () => {
    expect(() => auth.verify('invalid-token')).toThrow('Invalid token');
  });

  test('It should authenticate requests with valid JWT', async () => {
    await auth.createMagicLink({ email: TEST_EMAIL });
    const tokenKeys = await storageProvider.findKeys('magic_link:*');
    const token = tokenKeys[0].replace('magic_link:', '');

    const { accessToken } = await auth.verifyToken({
      token,
      email: TEST_EMAIL
    });

    const request = {
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    };

    const next = vi.fn();

    auth.authenticate(request, next);

    expect(next).toHaveBeenCalledWith();

    expect(request).toHaveProperty('user');
    // @ts-expect-error
    expect(request.user).toHaveProperty('email', TEST_EMAIL);
  });

  test('It should reject requests without authorization header', () => {
    const request = { headers: {} };
    const next = vi.fn();

    auth.authenticate(request, next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
    expect(next.mock.calls[0][0].message).toBe('Authentication required');
  });

  test('It should reject requests with invalid JWT', () => {
    const request = {
      headers: {
        authorization: 'Bearer invalid-token'
      }
    };

    const next = vi.fn();

    auth.authenticate(request, next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
    expect(next.mock.calls[0][0].message).toBe('Invalid or expired token');
  });
});

describe('Error handling', () => {
  test('It should handle invalid base URL', async () => {
    const config = { auth: { appUrl: 'invalid-url' } };
    const authWithInvalidUrl = new MikroAuth(
      // @ts-expect-error
      config,
      emailProvider,
      storageProvider
    );

    const request: MagicLinkRequest = {
      email: TEST_EMAIL
    };

    await expect(authWithInvalidUrl.createMagicLink(request)).rejects.toThrow(
      'Failed to process magic link request'
    );
  });

  test('It should handle storage exceptions gracefully', async () => {
    vi.spyOn(storageProvider, 'set').mockImplementationOnce(() => {
      throw new Error('Storage error');
    });

    const request: MagicLinkRequest = {
      email: TEST_EMAIL
    };

    await expect(() => auth.createMagicLink(request)).rejects.toThrowError(
      'Failed to process magic link request'
    );
  });
});

describe('Direct token creation', () => {
  test('It should create tokens directly without sending email', async () => {
    const request = {
      email: TEST_EMAIL,
      username: 'testuser',
      role: 'user',
      ip: '192.168.1.1'
    };

    const result = await auth.createToken(request);

    expect(result).toHaveProperty('accessToken');
    expect(result).toHaveProperty('refreshToken');
    expect(result).toHaveProperty('exp', TEST_JWT_EXPIRY);
    expect(result).toHaveProperty('tokenType', 'Bearer');

    const jwtService = new JsonWebToken(TEST_JWT_SECRET);
    const decoded = jwtService.verify(result.accessToken);

    expect(decoded.sub).toBe(TEST_EMAIL);
    expect(decoded.username).toBe('testuser');
    expect(decoded.role).toBe('user');
    expect(decoded).toHaveProperty('jti');
    expect(decoded).toHaveProperty('lastLogin');
    expect(decoded.metadata?.ip).toBe('192.168.1.1');

    const sessions = await storageProvider.getCollection(
      `sessions:${TEST_EMAIL}`
    );
    expect(sessions).toHaveLength(1);
    expect(sessions[0]).toBe(result.refreshToken);

    const refreshData = await storageProvider.get(
      `refresh:${result.refreshToken}`
    );
    expect(refreshData).not.toBeNull();

    const refreshMetadata = JSON.parse(refreshData ?? '{}');
    expect(refreshMetadata.email).toBe(TEST_EMAIL);
    expect(refreshMetadata.username).toBe('testuser');
    expect(refreshMetadata.role).toBe('user');
    expect(refreshMetadata.ipAddress).toBe('192.168.1.1');
    expect(refreshMetadata).toHaveProperty('tokenId');
    expect(refreshMetadata).toHaveProperty('createdAt');
    expect(refreshMetadata).toHaveProperty('lastLogin');
  });

  test('It should create tokens with minimal parameters', async () => {
    const request = {
      email: TEST_EMAIL
    };

    const result = await auth.createToken(request);

    expect(result).toHaveProperty('accessToken');
    expect(result).toHaveProperty('refreshToken');
    expect(result).toHaveProperty('exp', TEST_JWT_EXPIRY);
    expect(result).toHaveProperty('tokenType', 'Bearer');

    const jwtService = new JsonWebToken(TEST_JWT_SECRET);
    const decoded = jwtService.verify(result.accessToken);

    expect(decoded.sub).toBe(TEST_EMAIL);
    expect(decoded.username).toBeUndefined();
    expect(decoded.role).toBeUndefined();
    expect(decoded.metadata?.ip).toBe('unknown');
  });

  test('It should reject token creation with invalid email', async () => {
    const request = {
      email: 'invalid-email',
      username: 'testuser',
      role: 'user'
    };

    await expect(auth.createToken(request)).rejects.toThrow(
      'Valid email required'
    );
  });

  test('It should create tokens without IP and default to unknown', async () => {
    const request = {
      email: TEST_EMAIL,
      username: 'testuser',
      role: 'admin'
    };

    const result = await auth.createToken(request);

    const jwtService = new JsonWebToken(TEST_JWT_SECRET);
    const decoded = jwtService.verify(result.accessToken);

    expect(decoded.metadata?.ip).toBe('unknown');

    const refreshData = await storageProvider.get(
      `refresh:${result.refreshToken}`
    );
    const refreshMetadata = JSON.parse(refreshData ?? '{}');
    expect(refreshMetadata.ipAddress).toBe('unknown');
  });

  test('It should create valid access token that can be verified', async () => {
    const request = {
      email: TEST_EMAIL,
      username: 'testuser',
      role: 'user',
      ip: '10.0.0.1'
    };

    const { accessToken } = await auth.createToken(request);

    const payload = auth.verify(accessToken);

    expect(payload).toHaveProperty('sub', TEST_EMAIL);
    expect(payload).toHaveProperty('username', 'testuser');
    expect(payload).toHaveProperty('role', 'user');
    expect(payload).toHaveProperty('jti');
    expect(payload).toHaveProperty('lastLogin');
    expect(payload.metadata?.ip).toBe('10.0.0.1');
  });

  test('It should create refresh token that can be used to refresh access token', async () => {
    const request = {
      email: TEST_EMAIL,
      username: 'testuser',
      role: 'user',
      ip: '192.168.1.1'
    };

    const { refreshToken } = await auth.createToken(request);

    const refreshResult = await auth.refreshAccessToken(refreshToken);

    expect(refreshResult).toHaveProperty('accessToken');
    expect(refreshResult).toHaveProperty('refreshToken', refreshToken);
    expect(refreshResult).toHaveProperty('exp', TEST_JWT_EXPIRY);
    expect(refreshResult).toHaveProperty('tokenType', 'Bearer');

    const jwtService = new JsonWebToken(TEST_JWT_SECRET);
    const decoded = jwtService.verify(refreshResult.accessToken);

    expect(decoded.sub).toBe(TEST_EMAIL);
    expect(decoded.username).toBe('testuser');
    expect(decoded.role).toBe('user');
  });

  test('It should track session after token creation', async () => {
    const request = {
      email: TEST_EMAIL,
      username: 'testuser',
      role: 'user'
    };

    const { refreshToken } = await auth.createToken(request);

    const sessions = await storageProvider.getCollection(
      `sessions:${TEST_EMAIL}`
    );

    expect(sessions).toHaveLength(1);
    expect(sessions[0]).toBe(refreshToken);
  });

  test('It should respect max sessions limit when creating tokens', async () => {
    const request = {
      email: TEST_EMAIL,
      username: 'testuser',
      role: 'user'
    };

    const result1 = await auth.createToken(request);
    const result2 = await auth.createToken(request);
    const result3 = await auth.createToken(request);
    const result4 = await auth.createToken(request);

    const sessions = await storageProvider.getCollection(
      `sessions:${TEST_EMAIL}`
    );

    expect(sessions).toHaveLength(3);
    expect(sessions).not.toContain(result1.refreshToken);
    expect(sessions).toContain(result2.refreshToken);
    expect(sessions).toContain(result3.refreshToken);
    expect(sessions).toContain(result4.refreshToken);
  });

  test('It should allow logout with tokens created via createToken', async () => {
    const request = {
      email: TEST_EMAIL,
      username: 'testuser',
      role: 'user'
    };

    const { refreshToken } = await auth.createToken(request);

    const result = await auth.logout(refreshToken);

    expect(result).toHaveProperty('message', 'Logged out successfully.');

    const sessions = await storageProvider.getCollection(
      `sessions:${TEST_EMAIL}`
    );
    expect(sessions).not.toContain(refreshToken);

    const refreshData = await storageProvider.get(`refresh:${refreshToken}`);
    expect(refreshData).toBeNull();
  });

  test('It should create tokens that work with authenticate middleware', async () => {
    const request = {
      email: TEST_EMAIL,
      username: 'testuser',
      role: 'user'
    };

    const { accessToken } = await auth.createToken(request);

    const httpRequest = {
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    };

    const next = vi.fn();

    auth.authenticate(httpRequest, next);

    expect(next).toHaveBeenCalledWith();
    // @ts-expect-error
    expect(httpRequest.user).toHaveProperty('email', TEST_EMAIL);
  });

  test('It should handle storage errors during token creation', async () => {
    vi.spyOn(storageProvider, 'addToCollection').mockImplementationOnce(() => {
      throw new Error('Storage error');
    });

    const request = {
      email: TEST_EMAIL,
      username: 'testuser',
      role: 'user'
    };

    await expect(auth.createToken(request)).rejects.toThrow(
      'Token creation failed'
    );
  });

  test('It should create tokens with different roles', async () => {
    const roles = ['user', 'admin', 'moderator', 'guest'];

    for (const role of roles) {
      const request = {
        email: `${role}@example.com`,
        username: role,
        role: role
      };

      const { accessToken } = await auth.createToken(request);

      const jwtService = new JsonWebToken(TEST_JWT_SECRET);
      const decoded = jwtService.verify(accessToken);

      expect(decoded.role).toBe(role);
    }
  });

  test('It should not send any email when creating tokens', async () => {
    const initialEmailCount = emailProvider.getSentEmails().length;

    const request = {
      email: TEST_EMAIL,
      username: 'testuser',
      role: 'user'
    };

    await auth.createToken(request);

    const finalEmailCount = emailProvider.getSentEmails().length;
    expect(finalEmailCount).toBe(initialEmailCount);
  });

  test('It should not create any magic link tokens when using createToken', async () => {
    const request = {
      email: TEST_EMAIL,
      username: 'testuser',
      role: 'user'
    };

    await auth.createToken(request);

    const magicLinkKeys = await storageProvider.findKeys('magic_link:*');
    expect(magicLinkKeys).toHaveLength(0);
  });
});

describe('Edge cases', () => {
  test('It should handle requests with no IP', async () => {
    const request: MagicLinkRequest = {
      email: TEST_EMAIL
    };

    await auth.createMagicLink(request);

    const tokenKeys = await storageProvider.findKeys('magic_link:*');
    const tokenData = await storageProvider.get(tokenKeys[0]);
    const metadata = JSON.parse(tokenData ?? '{}');

    expect(metadata.ipAddress).toBe('unknown');
  });

  test('It should gracefully handle logout with non-existent refresh token', async () => {
    const refreshToken = 'non-existent-token';

    const result = await auth.logout(refreshToken);

    expect(result).toHaveProperty('message', 'Logged out successfully.');
  });
});
