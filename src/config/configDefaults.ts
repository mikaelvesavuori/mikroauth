export const configDefaults = () => {
  const debug = getTruthyValue(process.env.DEBUG) || false;

  return {
    auth: {
      jwtSecret: process.env.AUTH_JWT_SECRET || 'your-jwt-secret',
      magicLinkExpirySeconds: 15 * 60, // 15 minutes
      jwtExpirySeconds: 60 * 60, // 60 minutes
      refreshTokenExpirySeconds: 7 * 24 * 60 * 60, // 7 days
      maxActiveSessions: 3,
      appUrl: process.env.APP_URL || 'http://localhost:3000',
      templates: null,
      debug
    },
    email: {
      emailSubject: 'Your Secure Login Link',
      user: process.env.EMAIL_USER || '',
      host: process.env.EMAIL_HOST || '',
      password: process.env.EMAIL_PASSWORD || '',
      port: 465,
      secure: true,
      maxRetries: 2,
      debug
    },
    storage: {
      databaseDirectory: 'mikroauth',
      encryptionKey: process.env.STORAGE_KEY || '',
      debug
    },
    server: {
      port: Number(process.env.PORT) || 3000,
      host: process.env.HOST || '0.0.0.0',
      useHttps: false,
      useHttp2: false,
      sslCert: '',
      sslKey: '',
      sslCa: '',
      rateLimit: {
        enabled: true,
        requestsPerMinute: 100
      },
      allowedDomains: ['*'],
      debug
    }
  };
};

/**
 * @description Get a value and check if it's a string or boolean true.
 */
function getTruthyValue(value: string | boolean | undefined) {
  if (value === 'true' || value === true) return true;
  return false;
}
