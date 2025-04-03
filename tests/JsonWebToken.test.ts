import { beforeEach, describe, expect, test } from 'vitest';

import type { JwtClaims, JwtSignOptions } from '../src/interfaces/index.js';

import { JsonWebToken } from '../src/JsonWebToken.js';

// Constants for testing
const SECRET = 'super-secret-testing-key-at-least-32-chars-long';
const SHORT_SECRET = 'short';
const TEST_PAYLOAD: JwtClaims = {
  sub: 'user@example.com',
  name: 'Test User',
  role: 'admin',
  permissions: ['read', 'write']
};

let jwtService: JsonWebToken;

beforeEach(() => {
  jwtService = new JsonWebToken(SECRET);
});

describe('Initialization', () => {
  test('It should create a valid instance with a proper secret', () => {
    const service = new JsonWebToken(SECRET);
    expect(service).toBeInstanceOf(JsonWebToken);
  });

  test('It should warn when secret is too short', () => {
    process.env.NODE_ENV = 'production';
    expect(() => new JsonWebToken(SHORT_SECRET)).toThrowError();
    process.env.NODE_ENV = '';
  });
});

describe('Sign JWT token', () => {
  test('It should return a string with 3 parts separated by dots', () => {
    const token = jwtService.sign(TEST_PAYLOAD);
    expect(typeof token).toBe('string');
    expect(token.split('.')).toHaveLength(3);
  });

  test('It should include payload data in the token', () => {
    const token = jwtService.sign(TEST_PAYLOAD);
    const decoded = jwtService.decode(token);
    expect(decoded.payload.sub).toBe(TEST_PAYLOAD.sub);
    expect(decoded.payload.name).toBe(TEST_PAYLOAD.name);
    expect(decoded.payload.role).toBe(TEST_PAYLOAD.role);
    expect(decoded.payload.permissions).toEqual(TEST_PAYLOAD.permissions);
  });

  test('It should add iat (issued at) claim by default', () => {
    const nowInSeconds = Math.floor(Date.now() / 1000);
    const token = jwtService.sign(TEST_PAYLOAD);
    const decoded = jwtService.decode(token);

    // Allow 2 seconds of tolerance for test execution time
    expect(decoded.payload.iat).toBeGreaterThanOrEqual(nowInSeconds - 2);
    expect(decoded.payload.iat).toBeLessThanOrEqual(nowInSeconds + 2);
  });

  test('It should add exp (expiration) claim when exp option is provided', () => {
    const nowInSeconds = Math.floor(Date.now() / 1000);
    const exp = 3600; // 1 hour
    const options: JwtSignOptions = { exp };

    const token = jwtService.sign(TEST_PAYLOAD, options);
    const decoded = jwtService.decode(token);

    // Check expiration with 2 seconds tolerance
    expect(decoded.payload.exp).toBeGreaterThanOrEqual(nowInSeconds + exp - 2);
    expect(decoded.payload.exp).toBeLessThanOrEqual(nowInSeconds + exp + 2);
  });

  test('It should add all optional claims when options are provided', () => {
    const options: JwtSignOptions = {
      exp: 3600,
      notBefore: 60,
      issuer: 'test-issuer',
      audience: 'test-audience',
      subject: 'test-subject',
      jwtid: 'test-id-123'
    };

    const token = jwtService.sign(TEST_PAYLOAD, options);
    const decoded = jwtService.decode(token);

    const nowInSeconds = Math.floor(Date.now() / 1000);

    expect(decoded.payload.exp).toBeCloseTo(nowInSeconds + options.exp!, 1);
    expect(decoded.payload.nbf).toBeCloseTo(
      nowInSeconds + options.notBefore!,
      1
    );
    expect(decoded.payload.iss).toBe(options.issuer);
    expect(decoded.payload.aud).toBe(options.audience);
    expect(decoded.payload.sub).toBe(options.subject);
    expect(decoded.payload.jti).toBe(options.jwtid);
  });

  test('It should override payload properties with options', () => {
    // Payload has 'sub' already, but options should override it
    const options: JwtSignOptions = {
      subject: 'overridden-subject'
    };

    const token = jwtService.sign(TEST_PAYLOAD, options);
    const decoded = jwtService.decode(token);

    expect(decoded.payload.sub).toBe(options.subject);
  });
});

describe('Verify JWT token', () => {
  test('It should return the payload for a valid token', () => {
    const token = jwtService.sign(TEST_PAYLOAD);
    const payload = jwtService.verify(token);

    expect(payload.sub).toBe(TEST_PAYLOAD.sub);
    expect(payload.name).toBe(TEST_PAYLOAD.name);
    expect(payload.role).toBe(TEST_PAYLOAD.role);
  });

  test('It should throw error for invalid signature', () => {
    const token = jwtService.sign(TEST_PAYLOAD);
    const [header, payload, _] = token.split('.');
    const tampered = `${header}.${payload}.invalid-signature`;

    expect(() => jwtService.verify(tampered)).toThrow('Invalid signature');
  });

  test('It should throw error for expired token', () => {
    // Create token that expired 1 hour ago
    const nowInSeconds = Math.floor(Date.now() / 1000);
    const expiredToken = jwtService.sign({
      ...TEST_PAYLOAD,
      exp: nowInSeconds - 3600
    });

    expect(() => jwtService.verify(expiredToken)).toThrow('Token expired');
  });

  test('It should accept expired token within tolerance', () => {
    // Create token that expired 5 seconds ago
    const nowInSeconds = Math.floor(Date.now() / 1000);
    const expiredToken = jwtService.sign({
      ...TEST_PAYLOAD,
      exp: nowInSeconds - 5
    });

    // Should fail without tolerance
    expect(() => jwtService.verify(expiredToken)).toThrow('Token expired');

    // Should pass with 10 seconds tolerance
    const options = { clockTolerance: 10 };
    const payload = jwtService.verify(expiredToken, options);
    expect(payload.sub).toBe(TEST_PAYLOAD.sub);
  });

  test('It should throw error for token not yet valid', () => {
    // Create token that becomes valid in 1 hour
    const nowInSeconds = Math.floor(Date.now() / 1000);
    const futureToken = jwtService.sign({
      ...TEST_PAYLOAD,
      nbf: nowInSeconds + 3600
    });

    expect(() => jwtService.verify(futureToken)).toThrow('Token not yet valid');
  });

  test('It should throw error for invalid issuer', () => {
    const token = jwtService.sign(TEST_PAYLOAD, { issuer: 'issuer-1' });

    // Verify with different issuer
    expect(() => jwtService.verify(token, { issuer: 'issuer-2' })).toThrow(
      'Invalid issuer'
    );
  });

  test('It should throw error for invalid audience', () => {
    const token = jwtService.sign(TEST_PAYLOAD, { audience: 'audience-1' });

    // Verify with different audience
    expect(() => jwtService.verify(token, { audience: 'audience-2' })).toThrow(
      'Invalid audience'
    );
  });

  test('It should throw error for invalid subject', () => {
    const token = jwtService.sign(TEST_PAYLOAD, { subject: 'subject-1' });

    // Verify with different subject
    expect(() => jwtService.verify(token, { subject: 'subject-2' })).toThrow(
      'Invalid subject'
    );
  });

  test('It should throw error for invalid algorithm', () => {
    // Create a token with a manipulated header
    const token = jwtService.sign(TEST_PAYLOAD);
    const [_, payload, signature] = token.split('.');

    // Create fake header with different algorithm
    const fakeHeader = { alg: 'HS512', typ: 'JWT' };
    const encodedFakeHeader = Buffer.from(JSON.stringify(fakeHeader))
      .toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

    const tamperedToken = `${encodedFakeHeader}.${payload}.${signature}`;

    expect(() => jwtService.verify(tamperedToken)).toThrow(/Invalid algorithm/);
  });
});

describe('Decoding JWT token', () => {
  test('It should decode a valid token without verification', () => {
    const token = jwtService.sign(TEST_PAYLOAD);
    const decoded = jwtService.decode(token);

    expect(decoded.header.alg).toBe('HS256');
    expect(decoded.header.typ).toBe('JWT');
    expect(decoded.payload.sub).toBe(TEST_PAYLOAD.sub);
    expect(decoded.payload.name).toBe(TEST_PAYLOAD.name);
  });

  test('It should decode an expired token without error', () => {
    // Create token that expired 1 hour ago
    const nowInSeconds = Math.floor(Date.now() / 1000);
    const expiredToken = jwtService.sign({
      ...TEST_PAYLOAD,
      exp: nowInSeconds - 3600
    });

    // decode should work while verify would fail
    const decoded = jwtService.decode(expiredToken);
    expect(decoded.payload.sub).toBe(TEST_PAYLOAD.sub);
    expect(decoded.payload.exp).toBeLessThan(nowInSeconds);

    expect(() => jwtService.verify(expiredToken)).toThrow('Token expired');
  });

  test('It should throw error for invalid token format', () => {
    // Missing parts
    expect(() => jwtService.decode('header.payload')).toThrow(
      'Invalid token format'
    );

    // Too many parts
    expect(() => jwtService.decode('header.payload.signature.extra')).toThrow(
      'Invalid token format'
    );

    // Empty string
    expect(() => jwtService.decode('')).toThrow('Invalid token format');
  });

  test('It should throw error for malformed token parts', () => {
    // Invalid base64 in header
    expect(() => jwtService.decode('!@#$.payload.signature')).toThrow(
      'Failed to decode token'
    );

    // Invalid base64 in payload
    expect(() =>
      jwtService.decode('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.!@#$.signature')
    ).toThrow('Failed to decode token');

    // Invalid JSON in header
    const invalidJson = Buffer.from('{not valid json').toString('base64');
    expect(() => jwtService.decode(`${invalidJson}.payload.signature`)).toThrow(
      'Failed to decode token'
    );
  });
});

describe('Security tests', () => {
  test('Different secrets should produce different signatures', () => {
    const service1 = new JsonWebToken(SECRET);
    const service2 = new JsonWebToken(`${SECRET}different`);

    const token1 = service1.sign(TEST_PAYLOAD);
    const token2 = service2.sign(TEST_PAYLOAD);

    expect(token1).not.toBe(token2);

    // Token 1 should be verifiable with service 1 but not service 2
    expect(() => service1.verify(token1)).not.toThrow();
    expect(() => service2.verify(token1)).toThrow();

    // Token 2 should be verifiable with service 2 but not service 1
    expect(() => service2.verify(token2)).not.toThrow();
    expect(() => service1.verify(token2)).toThrow();
  });

  test('Same payload and secret should produce the same signature', () => {
    const service1 = new JsonWebToken(SECRET);
    const service2 = new JsonWebToken(SECRET);

    // To ensure deterministic output, provide a fixed timestamp
    const fixedPayload = {
      ...TEST_PAYLOAD,
      iat: 1677587233 // Fixed timestamp
    };

    // Skip automatic timestamp by adding our own
    const token1 = service1.sign(fixedPayload);
    const token2 = service2.sign(fixedPayload);

    expect(token1).toBe(token2);
  });

  test('It should not accept token signed with different algorithm', () => {
    // This is important for security to prevent algorithm downgrade attacks
    const token = jwtService.sign(TEST_PAYLOAD);
    const decoded = jwtService.decode(token);

    // Modify the header to claim it uses a different algorithm
    const modifiedHeader = { ...decoded.header, alg: 'none' };
    const modifiedHeaderB64 = Buffer.from(JSON.stringify(modifiedHeader))
      .toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

    const [_, payloadB64, signature] = token.split('.');
    const modifiedToken = `${modifiedHeaderB64}.${payloadB64}.${signature}`;

    // Should reject due to algorithm mismatch
    expect(() => jwtService.verify(modifiedToken)).toThrow(/Invalid algorithm/);
  });
});

describe('Base64Url encoding/decoding', () => {
  test('It should handle special characters properly', () => {
    const payloadWithSpecialChars = {
      ...TEST_PAYLOAD,
      specialChars: '!@#$%^&*()_+{}:"<>?[];\',./'
    };

    const token = jwtService.sign(payloadWithSpecialChars);
    const decoded = jwtService.decode(token);

    expect(decoded.payload.specialChars).toBe(
      payloadWithSpecialChars.specialChars
    );
  });

  test('It should handle Unicode characters properly', () => {
    const payloadWithUnicode = {
      ...TEST_PAYLOAD,
      unicode: '¡Unicode€★😀👍🏽'
    };

    const token = jwtService.sign(payloadWithUnicode);
    const decoded = jwtService.decode(token);

    expect(decoded.payload.unicode).toBe(payloadWithUnicode.unicode);
  });

  test('It should handle empty strings properly', () => {
    const payloadWithEmpty = {
      ...TEST_PAYLOAD,
      empty: ''
    };

    const token = jwtService.sign(payloadWithEmpty);
    const decoded = jwtService.decode(token);

    expect(decoded.payload.empty).toBe(payloadWithEmpty.empty);
  });
});

describe('Edge cases', () => {
  test('It should handle very short expiry times', () => {
    const jwtService = new JsonWebToken(SECRET);
    const token = jwtService.sign(TEST_PAYLOAD, { exp: 0.5 });

    expect(() => jwtService.verify(token)).not.toThrow();

    return new Promise<void>((resolve) => {
      setTimeout(() => {
        expect(() => jwtService.verify(token)).toThrow('Token expired');
        resolve();
      }, 1100);
    });
  });

  test('It should handle very large payloads', () => {
    // Create a large payload
    const largeArray = new Array(1000).fill(0).map((_, i) => `item-${i}`);
    const largePayload = {
      ...TEST_PAYLOAD,
      largeArray
    };

    const token = jwtService.sign(largePayload);
    const decoded = jwtService.decode(token);

    expect(decoded.payload.largeArray).toEqual(largeArray);
  });

  test('It should handle null values in payload', () => {
    const payloadWithNull = {
      ...TEST_PAYLOAD,
      nullValue: null
    };

    const token = jwtService.sign(payloadWithNull);
    const decoded = jwtService.decode(token);

    expect(decoded.payload.nullValue).toBeNull();
  });

  test('It should handle nested objects and arrays', () => {
    const complexPayload = {
      ...TEST_PAYLOAD,
      nested: {
        level1: {
          level2: {
            level3: 'deep value'
          },
          array: [1, 2, { nestedInArray: 'value' }]
        }
      }
    };

    const token = jwtService.sign(complexPayload);
    const decoded = jwtService.decode(token);

    expect(decoded.payload.nested.level1.level2.level3).toBe('deep value');
    expect(decoded.payload.nested.level1.array[2].nestedInArray).toBe('value');
  });
});
