import crypto from 'node:crypto';

import { configDefaults } from './config/configDefaults.js';
import type {
  DecodedJwt,
  JwtClaims,
  JwtHeader,
  JwtSignOptions,
  JwtVerifyOptions
} from './interfaces/index.js';

/**
 * @description Sign and verify JSON Web Tokens.
 */
export class JsonWebToken {
  private algorithm = 'HS256';
  private secret = 'HS256';

  /**
   * @param secret Secret key used for signing tokens.
   */
  constructor(secret: string) {
    if (
      process.env.NODE_ENV === 'production' &&
      (!secret ||
        secret.length < 32 ||
        secret === configDefaults().auth.jwtSecret)
    ) {
      throw new Error(
        'Production environment requires a strong JWT secret (min 32 chars)'
      );
    }

    this.secret = secret;
  }

  /**
   * @description Sign a payload and create a JWT token.
   * @param payload Data to encode in the token.
   * @param options Signing options.
   * @returns JWT token string.
   */
  public sign(payload: JwtClaims, options: JwtSignOptions = {}): string {
    const header: JwtHeader = {
      alg: this.algorithm,
      typ: 'JWT'
    };

    const now = Math.floor(Date.now() / 1000);

    const claims: JwtClaims = {
      ...payload,
      iat: now // Issued at
    };

    if (options.exp !== undefined) claims.exp = now + options.exp;
    if (options.notBefore !== undefined) claims.nbf = now + options.notBefore;
    if (options.issuer) claims.iss = options.issuer;
    if (options.audience) claims.aud = options.audience;
    if (options.subject) claims.sub = options.subject;
    if (options.jwtid) claims.jti = options.jwtid;

    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(claims));

    const dataToSign = `${encodedHeader}.${encodedPayload}`;
    const signature = this.createSignature(dataToSign);

    return `${dataToSign}.${signature}`;
  }

  /**
   * @description Verify a JWT token and return its payload.
   * @param token JWT token string.
   * @param options Verification options.
   * @returns Decoded payload.
   */
  public verify(token: string, options: JwtVerifyOptions = {}): JwtClaims {
    const decoded = this.decode(token);

    if (decoded.header.alg !== this.algorithm) {
      throw new Error(
        `Invalid algorithm. Expected ${this.algorithm}, got ${decoded.header.alg}`
      );
    }

    const [headerB64, payloadB64] = token.split('.');
    const dataToVerify = `${headerB64}.${payloadB64}`;
    const expectedSignature = this.createSignature(dataToVerify);

    if (expectedSignature !== decoded.signature)
      throw new Error('Invalid signature');

    const payload = decoded.payload;
    const now = Math.floor(Date.now() / 1000);
    const clockTolerance = options.clockTolerance || 0;

    if (payload.exp !== undefined && payload.exp + clockTolerance < now)
      throw new Error('Token expired');
    if (payload.nbf !== undefined && payload.nbf - clockTolerance > now)
      throw new Error('Token not yet valid');
    if (options.issuer && payload.iss !== options.issuer)
      throw new Error('Invalid issuer');
    if (options.audience && payload.aud !== options.audience)
      throw new Error('Invalid audience');
    if (options.subject && payload.sub !== options.subject)
      throw new Error('Invalid subject');

    return payload;
  }

  /**
   * @description Decode a JWT token without verification.
   * @param token JWT token string.
   */
  public decode(token: string): DecodedJwt {
    const parts = token.split('.');

    if (parts.length !== 3) throw new Error('Invalid token format');

    try {
      const [headerB64, payloadB64, signature] = parts;

      const header = JSON.parse(this.base64UrlDecode(headerB64));
      const payload = JSON.parse(this.base64UrlDecode(payloadB64));

      return {
        header,
        payload,
        signature
      };
    } catch (_error) {
      throw new Error('Failed to decode token');
    }
  }

  /**
   * @description Create a signature for the given data using HMAC-SHA256.
   * @param data Data to sign.
   * @returns Base64Url encoded signature.
   */
  private createSignature(data: string): string {
    const signature = crypto
      .createHmac('sha256', this.secret)
      .update(data)
      .digest();

    return this.base64UrlEncode(signature);
  }

  /**
   * @description Encode data to Base64Url.
   * @param data String or Buffer to encode.
   */
  private base64UrlEncode(data: string | Buffer): string {
    let buf: Buffer;

    if (typeof data === 'string') buf = Buffer.from(data);
    else buf = data;

    return buf
      .toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }

  /**
   * @description Decode Base64Url to string.
   * @param str Base64Url encoded string.
   */
  private base64UrlDecode(str: string): string {
    // Add padding if needed
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    switch (base64.length % 4) {
      case 0:
        break;
      case 2:
        base64 += '==';
        break;
      case 3:
        base64 += '=';
        break;
      default:
        throw new Error('Invalid base64 string');
    }

    return Buffer.from(base64, 'base64').toString();
  }
}
