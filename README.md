# MikroAuth

**Dead-simple magic link authentication that is useful, lightweight, and uncluttered**.

[![npm version](https://img.shields.io/npm/v/mikroauth.svg)](https://www.npmjs.com/package/mikroauth)

[![bundle size](https://img.shields.io/bundlephobia/minzip/mikroauth)](https://bundlephobia.com/package/mikroauth)

![Build Status](https://github.com/mikaelvesavuori/mikroauth/workflows/main/badge.svg)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

---

- Ever wanted to have your own Firebase Auth-like magic link authentication? Look no further, this is it!
- Secure magic link (email) login solution using JWTs
- Customizable text and HTML email templates
- Can be used as a library or exposed directly as an API
- Can be used with in-memory providers for storage and email or with providers for MikroDB and MikroMail
- Just ~11kb gzipped, using only four (max) lightweight dependencies:
  - [MikroConf](https://github.com/mikaelvesavuori/mikroconf) for handling config options;
  - [MikroDB](https://github.com/mikaelvesavuori/mikrodb) and [MikroMail](https://github.com/mikaelvesavuori/mikromail) for sending emails and persisting data;
  - [MikroServe](https://github.com/mikaelvesavuori/mikroserve) when exposing MikroAuth as an API.
- High test coverage

## Ecosystem

- [MikroAuth client library](https://github.com/mikaelvesavuori/mikroauth-client)
- [MikroAuth example](https://github.com/mikaelvesavuori/mikroauth-example) (requires MikroAuth running)

## Installation

```bash
npm install mikroauth -S
```

## Usage

### Quick Start

```typescript
import { MikroAuth } from 'mikroauth';

(async () => {
  // Uses in-memory providers by default if none are explicitly passed into MikroAuth
  const auth = new MikroAuth({
    appUrl: 'https://acmecorp.xyz/app',
    jwtSecret: 'your-secret-signing-key-for-jwts'
  });

  await auth.createMagicLink({
    email: 'sam.person@acmecorp.xyz'
  });

  // Close manually since there is a persistent event loop started by MikroAuth
  process.exit(0);
})();
```

### Example: Using Real Providers

```typescript
import { MikroAuth, MikroDBProvider, MikroMailProvider } from 'mikroauth';
import { MikroDB } from 'mikrodb';

(async () => {
  // Using MikroMail to send emails
  const email = new MikroMailProvider({
    user: 'me@mydomain.com',
    password: 'YOUR_PASSWORD_HERE',
    host: 'smtp.email-provider.com'
  });

  // Create a MikroDB provider by passing in an instance of MikroDB and starting it
  const storage = new MikroDBProvider(new MikroDB());
  await storage.start();

  // Initializing MikroAuth with our providers
  const auth = new MikroAuth(
    {
      appUrl: 'https://acmecorp.xyz/app',
      jwtSecret:  'your-secret-signing-key-for-jwts',
      // Additional options you can set
      magicLinkExpirySeconds: 15 * 60,
      jwtExpirySeconds: 60 * 60,
      refreshTokenExpirySeconds: 7 * 24 * 60 * 60,ys
      maxActiveSessions: 3,
      templates: null,
      debug: false
    },
    email,
    storage
  );

  await auth.createMagicLink({
    email: 'sam.person@acmecorp.xyz'
  });

  // Close manually since there is a persistent event loop started by MikroAuth
  process.exit(0);
})();
```

## How Magic Links Work

Magic links are a simple, yet powerful, [passwordless authentication](https://en.wikipedia.org/wiki/Passwordless_authentication) flow that works by sending a secure login link directly to the user's email. It's as simple as:

```text
┌────────┐                                      ┌────────┐
│  User  │                                      │ Server │
└───┬────┘                                      └───┬────┘
    │                                               │
    │ 1. Enter email address                        │
    │ ───────────────────────────────────────────►  X
    │                                               │
    │                                               │ 2. Generate unique token
    │                                               │    Store token with email
    │                                               │
    │ 3. Send email with magic link                 │
    X ◄───────────────────────────────────────────  │
    │                                               │
    │ 4. Click magic link                           │
    │ ───────────────────────────────────────────►  X
    │                                               │
    │                                               │ 5. Validate token
    │                                               │    Create session
    │                                               │
    │ 6. Return JWT + refresh token                 │
    X ◄───────────────────────────────────────────  │
    │                                               │
```

When a users request access, they provide only their email address. MikroAuth generates a cryptographically secure token (using SHA-256 with email, timestamp, and random data), stores it with an expiration time, and emails a link containing this token to the user.

Then, when the user clicks the link, MikroAuth validates the token, creates a session (JWT for authentication and a refresh token for maintaining the session), and logs them in securely - all without requiring a password.

MikroAuth also includes safeguards against abuse by invalidating existing magic links when new ones are requested, enforcing link expiration times, preventing token reuse, and managing multiple sessions for the same user.

---

## Configuration

Settings can be provided in multiple ways.

- They can be provided via the CLI, e.g. `node app.js --port 1234`.
- Certain values can be provided via environment variables.
  - Port: `process.env.PORT` - number
  - Host: `process.env.HOST` - string
  - Debug: `process.env.DEBUG` - boolean
- Programmatically/directly via scripting, e.g. `new MikroAuth({ port: 1234 })`.
- They can be placed in a configuration file named `mikroauth.config.json` (plain JSON), which will be automatically applied on load.

### Options

| CLI argument                | CLI value                                                     | JSON (config file) value           | Environment variable |
|-----------------------------|---------------------------------------------------------------|------------------------------------|----------------------|
| --jwtSecret                 | `<string>`                                                    | auth.jwtSecret                     | AUTH_JWT_SECRET      |
| --magicLinkExpirySeconds    | `<number>`                                                    | auth.magicLinkExpirySeconds        |                      |
| --jwtExpirySeconds          | `<number>`                                                    | auth.jwtExpirySeconds              |                      |
| --refreshTokenExpirySeconds | `<number>`                                                    | auth.refreshTokenExpirySeconds     |                      |
| --maxActiveSessions         | `<number>`                                                    | auth.maxActiveSessions             |                      |
|                             |                                                               | auth.templates                     |                      |
| --appUrl                    | `<string>`                                                    | auth.appUrl                        | APP_URL              |
| --debug                     | none (is flag)                                                | auth.debug                         | DEBUG                |
| --emailSubject              | `<string>`                                                    | email.emailSubject                 |                      |
| --emailHost                 | `<string>`                                                    | email.user                         | EMAIL_USER           |
| --emailUser                 | `<string>`                                                    | email.host                         | EMAIL_HOST           |
| --emailPassword             | `<string>`                                                    | email.password                     | EMAIL_PASSWORD       |
| --emailPort                 | `<number>`                                                    | email.port                         |                      |
| --emailSecure               | none (is flag)                                                | email.secure                       |                      |
| --emailMaxRetries           | `<number>`                                                    | email.maxRetries                   |                      |
| --debug                     | none (is flag)                                                | email.debug                        | DEBUG                |
| --dir                       | `<string>`                                                    | storage.databaseDirectory          |                      |
| --encryptionKey             | `<string>`                                                    | storage.encryptionKey              | STORAGE_KEY          |
| --debug                     | none (is flag)                                                | storage.debug                      | DEBUG                |
| --port                      | `<number>`                                                    | server.port                        | PORT                 |
| --host                      | `<string>`                                                    | server.host                        | HOST                 |
| --https                     | none (is flag)                                                | server.useHttps                    |                      |
| --http2                     | none (is flag)                                                | server.useHttp2                    |                      |
| --cert                      | `<string>`                                                    | server.sslCert                     |                      |
| --key                       | `<string>`                                                    | server.sslKey                      |                      |
| --ca                        | `<string>`                                                    | server.sslCa                       |                      |
| --ratelimit                 | none (is flag)                                                | server.rateLimit.enabled           |                      |
| --rps                       | `<number>`                                                    | server.rateLimit.requestsPerMinute |                      |
| --allowed                   | `<comma-separated strings>` (array of strings in JSON config) | server.allowedDomains              |                      |
| --debug                     | none (is flag)                                                | server.debug                       | DEBUG                |

_Setting debug mode in CLI arguments will enable debug mode across all areas. To granularly define this, use a config file._

### Order of Application

As per [MikroConf](https://github.com/mikaelvesavuori/mikroconf) behavior, the configuration sources are applied in this order:

1. Command line arguments (highest priority)
2. Programmatically provided config
3. Config file (JSON)
4. Default values (lowest priority)

### Magic Link Configuration

Defaults shown and explained.

```typescript
{
  // The base URL to use in the magic link, before appending "?token=TOKEN_VALUE&email=EMAIL_ADDRESS"
  appUrl: 'https://acmecorp.xyz/app',
  // Your secret JWT signing key
  jwtSecret:  'your-secret-signing-key-for-jwts',
  // Time until magic link expires (15 min)
  magicLinkExpirySeconds: 15 * 60,
  // Time until JWT expires (60 minutes)
  jwtExpirySeconds: 60 * 60,
  // Time until refresh token expires (7 days)
  refreshTokenExpirySeconds: 7 * 24 * 60 * 60,
  // How many active sessions can a user have?
  maxActiveSessions: 3,
  // Custom email templates to use
  templates: null,
  // Use debug mode?
  debug: false
}
```

Templates are passed in as an object with a function each to create the text and HTML versions of the magic link email.

```typescript
{
  // ...
  templates: {
    textVersion: (magicLink: string, expiryMinutes: number) =>
      `Sign in to your service. Go to ${magicLink} — the link expires in ${expiryMinutes} minutes.`,
    htmlVersion: (magicLink: string, expiryMinutes: number) =>
      `<h1>Sign in to your service</h1><p>Go to ${magicLink} — the link expires in ${expiryMinutes} minutes.</p>`
  }
}
```

### Email Configuration

Defaults shown and explained.

```typescript
{
  // The subject line for the email
  emailSubject: 'Your Secure Login Link',
  // The user identity sending the email from your email provider
  user: process.env.EMAIL_USER || '',
  // The SMTP host of your email provider
  host: process.env.EMAIL_HOST || '',
  // The password for the user identity
  password: process.env.EMAIL_PASSWORD || '',
  // The port to use (465 is default for "secure")
  port: 465,
  // If true, sets port to 465
  secure: true,
  // How many deliveries will be attempted?
  maxRetries: 2,
  // Use debug mode?
  debug: false
}
```

See [MikroMail](https://github.com/mikaelvesavuori/mikromail) for more details.

## Server Mode

MikroAuth has built-in functionality to be exposed directly as a server or API using [MikroServe](https://github.com/mikaelvesavuori/mikroserve).

Some nice features of running MikroAuth in server mode include:

- You get a zero-config-needed API for handling magic links
- JSON-based request and response format
- Configurable server options
- Support for both HTTP, HTTPS, and HTTP2
- Graceful shutdown handling

### Starting the Server (Command Line)

```bash
npx mikroauth
```

Configuring the server (API) settings follows the conventions of [MikroServe](https://github.com/mikaelvesavuori/mikroserve); please see that documentation for more details. In short, in this case, you can supply configuration in several ways:

- Configuration file, named `mikroauth.config.json`
- CLI arguments
- Environment variables

**The only difference compared to regular MikroServe usage is that the server configuration object (if used) must be nested in a `server` object, and authentication settings in an `auth` object**. For example, if you want to set the port value to 8080, your configuration would look like this:

```json
{
  "server": {
    "port": 8080
  },
  "auth": {
    "tokenExpiry": 3600,
    "refreshTokenExpiry": 86400
  }
}
```

### API Endpoints

#### Create Magic Link: Log In (Sign In)

```text
POST /login
```

Request body:

```json
{
  "email": "user@example.com"
}
```

Response:

```json
{
  "message": "Some informational message"
}
```

#### Verify Token

```text
POST /verify
```

Request body:

```json
{
  "email": "user@example.com"
}
```

Headers:

```text
Authorization: Bearer {token}
```

Response:

```json
{
  "accessToken": "jwt-token",
  "refreshToken": "refresh-token",
  "expiresIn": 3600,
  "tokenType": "Bearer"
}
```

#### Refresh Access Token

```text
POST /refresh
```

Request body:

```json
{
  "refreshToken": "refresh-token"
}
```

Response:

```json
{
  "accessToken": "new-jwt-token",
  "refreshToken": "new-refresh-token",
  "expiresIn": 3600,
  "tokenType": "Bearer"
}
```

#### Get Sessions

```text
GET /sessions
```

Headers:

```text
Authorization: Bearer {token}
```

Response:

```json
[
  {
    "id": "session-id",
    "createdAt": "timestamp",
    "lastLogin": "timestamp",
    "lastUsed": "timestamp",
    "metadata": {
      "ip": "127.0.0.1"
    },
    "isCurrentSession": true/false
  }
]
```

#### Revoke Sessions

```text
DELETE /sessions
```

Headers:

```text
Authorization: Bearer {token}
```

Request body:

```json
{
  "refreshToken": "refresh-token"
}
```

Response:

```json
{
  "message": "Some informational message"
}
```

#### Log Out (Sign Out)

```text
POST /logout
```

Headers:

```text
Authorization: Bearer {token}
```

Request body:

```json
{
  "refreshToken": "refresh-token-to-invalidate"
}
```

Response:

```json
{
  "message": "Some informational message"
}
```

### Error Handling

All endpoints return appropriate HTTP status codes:

- `200`: Success
- `401`: Unauthorized (missing or invalid token)
- `404`: Not found or operation failed
- `500`: Internal server error

### Providers

MikroAuth supports customizable providers for:

1. Email delivery - for sending magic links
2. Storage - for persisting tokens and sessions

By default, it uses in-memory providers suitable for development:

- `InMemoryEmailProvider`
- `InMemoryStorageProvider`

You can implement your own providers by following the interfaces defined in the package.

### Server Configuration

#### HTTPS/HTTP2 Configuration

To enable HTTPS or HTTP2, provide the following options when starting the server:

```javascript
const server = startServer({
  useHttps: true,
  // OR
  useHttp2: true,
  sslCert: '/path/to/certificate.pem',
  sslKey: '/path/to/private-key.pem',
  sslCa: '/path/to/ca-certificate.pem' // Optional
});
```

#### Generating Self-Signed Certificates (for testing)

```bash
# Generate a private key
openssl genrsa -out private-key.pem 2048

# Generate a certificate signing request
openssl req -new -key private-key.pem -out csr.pem

# Generate a self-signed certificate (valid for 365 days)
openssl x509 -req -days 365 -in csr.pem -signkey private-key.pem -out certificate.pem
```

## Future Ideas and Known Issues

- The MikroDB provider does not yet have the ability to remove expired items.
- WebAuthn support?
- Emit events (emails?) for failed auth and such things?
- Add artificial delay to simulate waiting when trying to login as non-existent user?

## License

MIT. See the `LICENSE` file.
