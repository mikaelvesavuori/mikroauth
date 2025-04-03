import { parsers } from 'mikroconf';

import { configDefaults } from './configDefaults';

const defaults = configDefaults();

export const mikroauthOptions = (customConfig?: Record<string, any>) => {
  const configuration: Record<string, any> = {
    configFilePath: 'mikroauth.config.json',
    args: process.argv,
    options: [
      // Auth configuration
      {
        flag: '--jwtSecret',
        path: 'auth.jwtSecret',
        defaultValue: defaults.auth.jwtSecret
      },
      {
        flag: '--magicLinkExpirySeconds',
        path: 'auth.magicLinkExpirySeconds',
        defaultValue: defaults.auth.magicLinkExpirySeconds
      },
      {
        flag: '--jwtExpirySeconds',
        path: 'auth.jwtExpirySeconds',
        defaultValue: defaults.auth.jwtExpirySeconds
      },
      {
        flag: '--refreshTokenExpirySeconds',
        path: 'auth.refreshTokenExpirySeconds',
        defaultValue: defaults.auth.refreshTokenExpirySeconds
      },
      {
        flag: '--maxActiveSessions',
        path: 'auth.maxActiveSessions',
        defaultValue: defaults.auth.maxActiveSessions
      },
      {
        flag: '--appUrl',
        path: 'auth.appUrl',
        defaultValue: defaults.auth.appUrl
      },
      {
        flag: '--debug',
        path: 'auth.debug',
        isFlag: true,
        defaultValue: defaults.auth.debug
      },
      // Email configuration
      {
        flag: '--emailSubject',
        path: 'email.emailSubject',
        defaultValue: 'Your Secure Login Link'
      },
      {
        flag: '--emailHost',
        path: 'email.host',
        defaultValue: defaults.email.host
      },
      {
        flag: '--emailUser',
        path: 'email.user',
        defaultValue: defaults.email.user
      },
      {
        flag: '--emailPassword',
        path: 'email.password',
        defaultValue: defaults.email.password
      },
      {
        flag: '--emailPort',
        path: 'email.port',
        defaultValue: defaults.email.port
      },
      {
        flag: '--emailSecure',
        path: 'email.secure',
        isFlag: true,
        defaultValue: defaults.email.secure
      },
      {
        flag: '--emailMaxRetries',
        path: 'email.maxRetries',
        defaultValue: defaults.email.maxRetries
      },
      {
        flag: '--debug',
        path: 'email.debug',
        isFlag: true,
        defaultValue: defaults.email.debug
      },
      // Storage configuration
      {
        flag: '--dir',
        path: 'storage.databaseDirectory',
        defaultValue: defaults.storage.databaseDirectory
      },
      {
        flag: '--encryptionKey',
        path: 'storage.encryptionKey',
        defaultValue: defaults.storage.encryptionKey
      },
      {
        flag: '--debug',
        path: 'storage.debug',
        defaultValue: defaults.storage.debug
      },
      // Server configuration
      {
        flag: '--port',
        path: 'server.port',
        defaultValue: defaults.server.port
      },
      {
        flag: '--host',
        path: 'server.host',
        defaultValue: defaults.server.host
      },
      {
        flag: '--https',
        path: 'server.useHttps',
        isFlag: true,
        defaultValue: defaults.server.useHttps
      },
      {
        flag: '--https',
        path: 'server.useHttp2',
        isFlag: true,
        defaultValue: defaults.server.useHttp2
      },
      {
        flag: '--cert',
        path: 'server.sslCert',
        defaultValue: defaults.server.sslCert
      },
      {
        flag: '--key',
        path: 'server.sslKey',
        defaultValue: defaults.server.sslKey
      },
      {
        flag: '--ca',
        path: 'server.sslCa',
        defaultValue: defaults.server.sslCa
      },
      {
        flag: '--ratelimit',
        path: 'server.rateLimit.enabled',
        defaultValue: defaults.server.rateLimit.enabled,
        isFlag: true
      },
      {
        flag: '--rps',
        path: 'server.rateLimit.requestsPerMinute',
        defaultValue: defaults.server.rateLimit.requestsPerMinute
      },
      {
        flag: '--allowed',
        path: 'server.allowedDomains',
        defaultValue: defaults.server.allowedDomains,
        parser: parsers.array
      },
      {
        flag: '--debug',
        path: 'server.debug',
        isFlag: true,
        defaultValue: defaults.server.debug
      }
    ]
  };

  if (customConfig) configuration.config = customConfig;

  return configuration;
};
