import crypto from 'node:crypto';
import { URL } from 'node:url';
import { MikroConf } from 'mikroconf';

import type {
  AuthOptions,
  CombinedConfiguration,
  CreateTokenRequest,
  EmailOptions,
  EmailProvider,
  JwtPayload,
  MagicLinkRequest,
  MagicLinkUrlParams,
  RequestContext,
  SessionInfo,
  StorageProvider,
  TokenResponse,
  UserIdentity,
  VerifyTokenRequest
} from './interfaces/index.js';

import { JsonWebToken } from './JsonWebToken.js';
import { MagicLinkEmailTemplates } from './MagicLinkEmailTemplates.js';

import { InMemoryEmailProvider } from './providers/InMemoryEmailProvider.js';
import { InMemoryStorageProvider } from './providers/InMemoryStorageProvider.js';

import { isValidEmail } from './utils/isValidEmail.js';

import { configDefaults } from './config/configDefaults.js';
import { mikroauthOptions } from './config/mikroauthOptions.js';

const messages = {
  linkSent: 'If a matching account was found, a magic link has been sent.',
  revokedSuccess: 'All other sessions revoked successfully.',
  logoutSuccess: 'Logged out successfully.'
};

/**
 * @description MikroAuth is a dead-simple "Magic Link"
 * authentication service that works with your storage and email.
 */
export class MikroAuth {
  private readonly config: CombinedConfiguration;
  private readonly email: EmailProvider;
  private readonly storage: StorageProvider;
  private readonly jwtService: JsonWebToken;
  private readonly templates: MagicLinkEmailTemplates;

  constructor(
    options: { auth: AuthOptions; email: EmailOptions },
    emailProvider?: EmailProvider,
    storageProvider?: StorageProvider
  ) {
    const config = new MikroConf(
      mikroauthOptions({ auth: options.auth, email: options.email })
    ).get() as CombinedConfiguration;
    if (config.auth.debug) console.log('Using configuration:', config);
    this.config = config;

    this.email = emailProvider || new InMemoryEmailProvider();
    this.storage = storageProvider || new InMemoryStorageProvider();
    this.jwtService = new JsonWebToken(config.auth.jwtSecret);
    this.templates = new MagicLinkEmailTemplates(config?.auth.templates);

    this.checkIfUsingDefaultCredentialsInProduction();
  }

  /**
   * @description Verify that we are not using defaults.
   */
  private checkIfUsingDefaultCredentialsInProduction() {
    if (
      process.env.NODE_ENV === 'production' &&
      this.config.auth.jwtSecret === configDefaults().auth.jwtSecret
    ) {
      console.error(
        'WARNING: Using default secrets in production environment!'
      );
      process.exit(1);
    }
  }

  /**
   * @description Generates a secure token.
   */
  public generateToken(email: string): string {
    const timestamp = Date.now().toString();
    const random = crypto.randomBytes(32).toString('hex');

    return crypto
      .createHash('sha256')
      .update(`${email}:${timestamp}:${random}`)
      .digest('hex');
  }

  /**
   * @description Generate a JWT for an authenticated user.
   */
  public generateJsonWebToken(user: UserIdentity): string {
    return this.jwtService.sign({
      sub: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24
    });
  }

  /**
   * @description Generates a refresh token.
   */
  private generateRefreshToken(): string {
    return crypto.randomBytes(40).toString('hex');
  }

  /**
   * @description Tracks a user session in storage.
   */
  private async trackSession(
    email: string,
    refreshToken: string,
    metadata: Record<string, any>
  ): Promise<void> {
    const sessionKey = `sessions:${email}`;
    const size = await this.storage.getCollectionSize(sessionKey);

    // Remove oldest session if at max capacity
    if (size >= this.config.auth.maxActiveSessions) {
      const oldestToken =
        await this.storage.removeOldestFromCollection(sessionKey);
      if (oldestToken) await this.storage.delete(`refresh:${oldestToken}`);
    }

    await this.storage.addToCollection(
      sessionKey,
      refreshToken,
      this.config.auth.refreshTokenExpirySeconds
    );

    await this.storage.set(
      `refresh:${refreshToken}`,
      JSON.stringify(metadata),
      this.config.auth.refreshTokenExpirySeconds
    );
  }

  /**
   * @description Creates the actual magic link URL, using the token and email.
   */
  private generateMagicLinkUrl(params: MagicLinkUrlParams): string {
    const { token, email } = params;

    try {
      new URL(this.config.auth.appUrl); // Validate base URL format
      return `${this.config.auth.appUrl}?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`;
    } catch (_error) {
      throw new Error('Invalid base URL configuration');
    }
  }

  /**
   * @description Creates and sends a magic link to the user.
   */
  public async createMagicLink(
    params: MagicLinkRequest
  ): Promise<{ message: string }> {
    const { email, ip } = params;

    if (!isValidEmail(email)) throw new Error('Valid email required');

    try {
      const token = this.generateToken(email);
      const userKey = `magic_link:${token}`;

      const metadata = {
        email,
        ipAddress: ip || 'unknown',
        createdAt: Date.now()
      };

      await this.storage.set(
        userKey,
        JSON.stringify(metadata),
        this.config.auth.magicLinkExpirySeconds
      );

      // Invalidate existing magic links for this email to prevent abuse
      const existingTokens = await this.storage.findKeys('magic_link:*');
      for (const key of existingTokens) {
        if (key === userKey) continue;

        const data = await this.storage.get(key);

        if (data) {
          try {
            const parsed = JSON.parse(data);
            if (parsed.email === email) await this.storage.delete(key);
          } catch (_error) {
            // Ignore parsing errors for invalid JSON
          }
        }
      }

      const magicLink = this.generateMagicLinkUrl({ token, email });
      const expiryMinutes = Math.ceil(
        this.config.auth.magicLinkExpirySeconds / 60
      );

      await this.email.sendMail({
        from: this.config.email.user,
        to: email,
        subject: this.config.email.emailSubject,
        text: this.templates.getText(magicLink, expiryMinutes),
        html: this.templates.getHtml(magicLink, expiryMinutes)
      });

      return { message: messages.linkSent };
    } catch (error) {
      console.error(`Failed to process magic link request: ${error}`);
      throw new Error('Failed to process magic link request');
    }
  }

  /**
   * @description Creates credentials/tokens directly without sending an email.
   * This method is useful for programmatic use cases such as SSO integrations,
   * where you need to authenticate a user and obtain tokens directly without
   * going through the magic link flow.
   */
  public async createToken(params: CreateTokenRequest): Promise<TokenResponse> {
    const { email, username, role, ip } = params;

    if (!isValidEmail(email)) throw new Error('Valid email required');

    try {
      const tokenId = crypto.randomBytes(16).toString('hex');
      const refreshToken = this.generateRefreshToken();
      const createdAt = Date.now();

      const payload: JwtPayload = {
        sub: email,
        username: username,
        role: role,
        jti: tokenId,
        lastLogin: createdAt,
        metadata: {
          ip: ip || 'unknown'
        },
        exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 // 24 hours
      };

      const accessToken = this.jwtService.sign(payload, {
        exp: this.config.auth.jwtExpirySeconds
      });

      const metadata = {
        email,
        username,
        role,
        ipAddress: ip || 'unknown',
        tokenId,
        createdAt,
        lastLogin: createdAt
      };

      await this.trackSession(email, refreshToken, metadata);

      return {
        accessToken,
        refreshToken,
        exp: this.config.auth.jwtExpirySeconds,
        tokenType: 'Bearer'
      };
    } catch (error) {
      console.error('Token creation error:', error);
      throw new Error('Token creation failed');
    }
  }

  /**
   * @description Verifies a magic link token and creates session tokens.
   */
  public async verifyToken(params: VerifyTokenRequest): Promise<TokenResponse> {
    const { token, email } = params;

    try {
      const userKey = `magic_link:${token}`;

      const storedData = await this.storage.get(userKey);
      if (!storedData) throw new Error('Invalid or expired token');

      const metadata = JSON.parse(storedData);
      if (metadata.email !== email) throw new Error('Email mismatch');

      const username = metadata.username;
      const role = metadata.role;

      await this.storage.delete(userKey); // Delete the token to prevent reuse

      const tokenId = crypto.randomBytes(16).toString('hex');
      const refreshToken = this.generateRefreshToken();

      const payload: JwtPayload = {
        sub: email,
        username: username,
        role: role,
        jti: tokenId,
        lastLogin: metadata.createdAt,
        metadata: {
          ip: metadata.ipAddress
        },
        exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 // 24 hours
      };

      const accessToken = this.jwtService.sign(payload, {
        exp: this.config.auth.jwtExpirySeconds
      });

      await this.trackSession(email, refreshToken, {
        ...metadata,
        tokenId,
        createdAt: Date.now()
      });

      const result = {
        accessToken,
        refreshToken,
        exp: this.config.auth.jwtExpirySeconds,
        tokenType: 'Bearer'
      };

      return result;
    } catch (error) {
      console.error('Token verification error:', error);
      throw new Error('Verification failed');
    }
  }

  /**
   * @description Refreshes an access token using a refresh token.
   */
  public async refreshAccessToken(
    refreshToken: string
  ): Promise<TokenResponse> {
    try {
      const refreshData = await this.storage.get(`refresh:${refreshToken}`);
      if (!refreshData) throw new Error('Invalid or expired refresh token');

      const metadata = JSON.parse(refreshData);
      const email = metadata.email;

      if (!email) throw new Error('Invalid refresh token data');

      const username = metadata.username;
      const role = metadata.role;

      const tokenId = crypto.randomBytes(16).toString('hex');

      const payload: JwtPayload = {
        sub: email,
        username,
        role,
        jti: tokenId,
        lastLogin: metadata.lastLogin || metadata.createdAt,
        metadata: {
          ip: metadata.ipAddress
        }
      };

      const accessToken = this.jwtService.sign(payload, {
        exp: this.config.auth.jwtExpirySeconds
      });

      metadata.lastUsed = Date.now();
      await this.storage.set(
        `refresh:${refreshToken}`,
        JSON.stringify(metadata),
        this.config.auth.refreshTokenExpirySeconds
      );

      return {
        accessToken,
        refreshToken,
        exp: this.config.auth.jwtExpirySeconds,
        tokenType: 'Bearer'
      };
    } catch (error) {
      console.error('Token refresh error:', error);
      throw new Error('Token refresh failed');
    }
  }

  /**
   * @description Verifies a JWT token.
   */
  public verify(token: string): JwtPayload {
    try {
      const payload = this.jwtService.verify(token);
      return payload as JwtPayload;
    } catch (_error) {
      throw new Error('Invalid token');
    }
  }

  /**
   * @description Logs out a user by revoking their session token.
   */
  public async logout(refreshToken: string): Promise<{ message: string }> {
    try {
      if (!refreshToken || typeof refreshToken !== 'string')
        throw new Error('Refresh token is required');

      const refreshData = await this.storage.get(`refresh:${refreshToken}`);

      if (!refreshData) return { message: messages.logoutSuccess }; // Token already expired/invalid

      const metadata = JSON.parse(refreshData);
      const email = metadata.email;

      if (!email) throw new Error('Invalid refresh token data');

      await this.storage.delete(`refresh:${refreshToken}`);

      const sessionKey = `sessions:${email}`;
      await this.storage.removeFromCollection(sessionKey, refreshToken);

      return { message: messages.logoutSuccess };
    } catch (error) {
      console.error('Logout error:', error);
      throw new Error('Logout failed');
    }
  }

  /**
   * @description Gets all active sessions for a user.
   */
  public async getSessions(
    request: RequestContext
  ): Promise<{ sessions: SessionInfo[] }> {
    try {
      if (!request.user?.email) throw new Error('User not authenticated');

      const email = request.user.email;
      const currentRefreshToken = request.body?.refreshToken;
      const sessionKey = `sessions:${email}`;
      const refreshTokens = await this.storage.getCollection(sessionKey);

      const sessionsPromises = refreshTokens.map(async (token) => {
        try {
          const data = await this.storage.get(`refresh:${token}`);

          if (!data) {
            // Remove invalid tokens
            await this.storage.removeFromCollection(sessionKey, token);
            return null;
          }

          const metadata = JSON.parse(data);

          return {
            id: `${token.substring(0, 8)}...`, // Only show part of the token for security
            createdAt: metadata.createdAt || 0,
            lastLogin: metadata.lastLogin || metadata.createdAt || 0,
            lastUsed: metadata.lastUsed || metadata.createdAt || 0,
            metadata: {
              ip: metadata.ipAddress
            },
            isCurrentSession: token === currentRefreshToken
          };
        } catch (_error) {
          // Remove invalid tokens
          await this.storage.removeFromCollection(sessionKey, token);
          return null;
        }
      });

      const sessions = (await Promise.all(sessionsPromises)).filter(
        Boolean
      ) as SessionInfo[];

      // Sort sessions by creation time, newest first
      sessions.sort((a, b) => b.createdAt - a.createdAt);

      return { sessions };
    } catch (error) {
      console.error('Get sessions error:', error);
      throw new Error('Failed to fetch sessions');
    }
  }

  /**
   * @description Revokes all active sessions for a user.
   */
  public async revokeSessions(
    request: RequestContext
  ): Promise<{ message: string }> {
    try {
      if (!request.user?.email) throw new Error('User not authenticated');

      const email = request.user.email;
      const currentRefreshToken = request.body?.refreshToken;
      const sessionKey = `sessions:${email}`;
      const refreshTokens = await this.storage.getCollection(sessionKey);

      // Delete all refresh tokens except the current one if specified
      for (const token of refreshTokens) {
        if (currentRefreshToken && token === currentRefreshToken) continue; // Skip the current session if we want to keep it
        await this.storage.delete(`refresh:${token}`);
      }

      // Clear the sessions collection
      await this.storage.delete(sessionKey);

      // Add back the current session if needed
      if (currentRefreshToken) {
        const refreshData = await this.storage.get(
          `refresh:${currentRefreshToken}`
        );

        if (refreshData) {
          await this.storage.addToCollection(
            sessionKey,
            currentRefreshToken,
            this.config.auth.refreshTokenExpirySeconds
          );
        }
      }

      return { message: messages.revokedSuccess };
    } catch (error) {
      console.error('Revoke sessions error:', error);
      throw new Error('Failed to revoke sessions');
    }
  }

  /**
   * @description Middleware to authenticate requests with JWT tokens.
   */
  public authenticate(request: any, next: (error?: Error) => void): void {
    try {
      const authHeader = request.headers?.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer '))
        throw new Error('Authentication required');

      const token = authHeader.split(' ')[1];

      try {
        const payload = this.verify(token);
        request.user = { email: payload.sub };
        next();
      } catch (_error) {
        throw new Error('Invalid or expired token');
      }
    } catch (error) {
      next(error as Error);
    }
  }
}
