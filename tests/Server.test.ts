import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

// Set up mocks before any imports
const mockEndpoints = new Map();

// Mock MikroServe
vi.mock('mikroserve', () => ({
  MikroServe: class {
    get = vi.fn((path: string, handler: any) =>
      mockEndpoints.set(`GET ${path}`, handler)
    );
    post = vi.fn((path: string, handler: any) =>
      mockEndpoints.set(`POST ${path}`, handler)
    );
    delete = vi.fn((path: string, handler: any) =>
      mockEndpoints.set(`DELETE ${path}`, handler)
    );
    start = vi.fn();
    stop = vi.fn();
    port = 3000;
    isReady = true;
    on = vi.fn();
  }
}));

// Mock MikroAuth
vi.mock('../src/MikroAuth', () => ({
  MikroAuth: class {
    createMagicLink = vi.fn().mockResolvedValue({
      message: 'If a matching account was found, a magic link has been sent'
    });
    verifyToken = vi.fn().mockImplementation(({ email, token }: any) => {
      if (email === 'test@example.com' && token !== 'invalid-token') {
        return Promise.resolve({
          accessToken: 'mock-access-token',
          refreshToken: 'mock-refresh-token'
        });
      }
      return Promise.resolve(null);
    });
    refreshAccessToken = vi.fn().mockImplementation((token: string) => {
      if (token === 'mock-refresh-token') {
        return Promise.resolve({
          accessToken: 'new-mock-access-token'
        });
      }
      return Promise.resolve(null);
    });
    logout = vi.fn().mockResolvedValue({ success: true });
    verify = vi.fn().mockReturnValue({ sub: 'test@example.com' });
    getSessions = vi.fn().mockResolvedValue({
      sessions: [{ id: 'session-1' }, { id: 'session-2' }]
    });
    revokeSessions = vi.fn().mockResolvedValue({
      message: 'All other sessions revoked successfully.'
    });
  }
}));

// Mock providers
vi.mock('../src/providers/InMemoryEmailProvider', () => ({
  InMemoryEmailProvider: class {
    getSentEmails = vi
      .fn()
      .mockReturnValue([
        { to: 'test@example.com', subject: 'Your Magic Link', body: 'token123' }
      ]);
    sendEmail = vi.fn().mockResolvedValue(true);
  }
}));

vi.mock('../src/providers/InMemoryStorageProvider', () => ({
  InMemoryStorageProvider: class {
    findKeys = vi.fn().mockImplementation((pattern) => {
      if (pattern === 'magic_link:*') {
        return Promise.resolve(['magic_link:token123', 'magic_link:token456']);
      }
      return Promise.resolve([]);
    });
    delete = vi.fn().mockResolvedValue(true);
    get = vi
      .fn()
      .mockResolvedValue(JSON.stringify({ email: 'test@example.com' }));
    set = vi.fn().mockResolvedValue(true);
  }
}));

// Import after mocks are established
import { startServer } from '../src/Server.js';
import { InMemoryEmailProvider } from '../src/providers/InMemoryEmailProvider.js';
import { InMemoryStorageProvider } from '../src/providers/InMemoryStorageProvider.js';

// Helper for creating context objects
function createContext(method: string, path: string, body = {}, headers = {}) {
  return {
    req: {
      method,
      path,
      body,
      headers,
      socket: { remoteAddress: '127.0.0.1' }
    },
    json: vi.fn((response) => response)
  };
}

describe('MikroAuth Server', () => {
  let server: any;
  let email: any;
  let storage: any;

  beforeEach(() => {
    mockEndpoints.clear();
    vi.clearAllMocks();

    email = new InMemoryEmailProvider();
    storage = new InMemoryStorageProvider();

    const config = {
      auth: {
        jwtExpirySeconds: 60,
        refreshTokenExpirySeconds: 120,
        magicLinkExpirySeconds: 60
      },
      email: {},
      server: {
        port: 3000,
        host: 'localhost',
        useHttps: false,
        debug: false,
        rateLimit: {
          requestsPerMinute: 1000,
          enabled: true
        },
        allowedDomains: ['*']
      },
      storage: {}
    };

    // @ts-expect-error
    server = startServer(config, email, storage);
  });

  afterEach(() => {
    if (server?.stop) server.stop();
  });

  test('should initialize server with correct configuration', () => {
    expect(server).toBeDefined();
  });

  test('should register API endpoints', () => {
    expect(mockEndpoints.has('POST /login')).toBe(true);
    expect(mockEndpoints.has('POST /verify')).toBe(true);
    expect(mockEndpoints.has('POST /refresh')).toBe(true);
    expect(mockEndpoints.has('POST /logout')).toBe(true);
    expect(mockEndpoints.has('GET /sessions')).toBe(true);
    expect(mockEndpoints.has('DELETE /sessions')).toBe(true);
  });

  test('POST /login should handle successful magic link creation', async () => {
    const handler = mockEndpoints.get('POST /login');
    const ctx = createContext('POST', '/login', {
      email: 'test@example.com'
    });

    await handler(ctx);

    expect(ctx.json).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.stringContaining('magic link has been sent')
      }),
      200
    );
  });

  test('POST /verify should handle successful token verification', async () => {
    const handler = mockEndpoints.get('POST /verify');
    const ctx = createContext(
      'POST',
      '/verify',
      { email: 'test@example.com' },
      { authorization: 'Bearer valid-token' }
    );

    await handler(ctx);

    expect(ctx.json).toHaveBeenCalledWith(
      expect.objectContaining({
        accessToken: expect.any(String),
        refreshToken: expect.any(String)
      }),
      200
    );
  });

  test('POST /verify should return 404 for invalid tokens', async () => {
    const handler = mockEndpoints.get('POST /verify');
    const ctx = createContext(
      'POST',
      '/verify',
      { email: 'test@example.com' },
      { authorization: 'Bearer invalid-token' }
    );

    await handler(ctx);

    expect(ctx.json).toHaveBeenCalledWith(null, 404);
  });

  test('POST /refresh should handle token refresh', async () => {
    const handler = mockEndpoints.get('POST /refresh');
    const ctx = createContext('POST', '/refresh', {
      refreshToken: 'mock-refresh-token'
    });

    await handler(ctx);

    expect(ctx.json).toHaveBeenCalledWith(
      expect.objectContaining({
        accessToken: expect.any(String)
      }),
      200
    );
  });

  test('POST /logout should handle logout', async () => {
    const handler = mockEndpoints.get('POST /logout');
    const ctx = createContext(
      'POST',
      '/logout',
      { refreshToken: 'mock-refresh-token' },
      { authorization: 'Bearer mock-access-token' }
    );

    await handler(ctx);

    expect(ctx.json).toHaveBeenCalledWith(
      expect.objectContaining({ success: true }),
      200
    );
  });

  test('POST /logout should return 401 without authorization', async () => {
    const handler = mockEndpoints.get('POST /logout');
    const ctx = createContext('POST', '/logout', {
      refreshToken: 'mock-refresh-token'
    });

    await handler(ctx);

    expect(ctx.json).toHaveBeenCalledWith(null, 401);
  });

  test('GET /sessions should return user sessions', async () => {
    const handler = mockEndpoints.get('GET /sessions');
    const ctx = createContext(
      'GET',
      '/sessions',
      {},
      { authorization: 'Bearer mock-access-token' }
    );

    await handler(ctx);

    expect(ctx.json).toHaveBeenCalledWith(
      expect.objectContaining({
        sessions: expect.arrayContaining([
          expect.objectContaining({ id: 'session-1' }),
          expect.objectContaining({ id: 'session-2' })
        ])
      }),
      200
    );
  });

  test('GET /sessions should return 401 without authorization', async () => {
    const handler = mockEndpoints.get('GET /sessions');
    const ctx = createContext('GET', '/sessions');

    await handler(ctx);

    expect(ctx.json).toHaveBeenCalledWith(null, 401);
  });

  test('DELETE /sessions should revoke other sessions', async () => {
    const handler = mockEndpoints.get('DELETE /sessions');
    const ctx = createContext(
      'DELETE',
      '/sessions',
      {},
      { authorization: 'Bearer mock-access-token' }
    );

    await handler(ctx);

    expect(ctx.json).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'All other sessions revoked successfully.'
      }),
      200
    );
  });

  test('DELETE /sessions should return 401 without authorization', async () => {
    const handler = mockEndpoints.get('DELETE /sessions');
    const ctx = createContext('DELETE', '/sessions');

    await handler(ctx);

    expect(ctx.json).toHaveBeenCalledWith(null, 401);
  });
});
