import { MikroConf } from 'mikroconf';
import { MikroDB } from 'mikrodb';
import { MikroServe } from 'mikroserve';

import type {
  CombinedConfiguration,
  EmailProvider,
  StorageProvider
} from './interfaces/index.js';

import { MikroAuth } from './MikroAuth.js';

import { InMemoryEmailProvider } from './providers/InMemoryEmailProvider.js';
import { InMemoryStorageProvider } from './providers/InMemoryStorageProvider.js';
import { MikroDBProvider } from './providers/MikroDBProvider.js';
import { MikroMailProvider } from './providers/MikroMailProvider.js';

import { mikroauthOptions } from './config/mikroauthOptions.js';

/**
 * @description Wires up MikroAuth with Mikro-family providers for other needed features.
 */
export async function startServerWithMikroProviders() {
  const config = new MikroConf(
    mikroauthOptions()
  ).get() as CombinedConfiguration;

  const email = new MikroMailProvider(config.email);

  const storage = new MikroDBProvider(new MikroDB(config.storage));
  await storage.start();

  await startServer(config, email, storage);
}

/**
 * @description Starts up MikroServe for serving MikroAuth.
 */
export async function startServer(
  config: CombinedConfiguration,
  emailProvider?: EmailProvider,
  storageProvider?: StorageProvider
) {
  const storage = storageProvider || new InMemoryStorageProvider();
  const email = emailProvider || new InMemoryEmailProvider();

  const auth = new MikroAuth(config, email, storage);
  const server = new MikroServe(config.server);

  server.post('/login', async (c: any) => {
    const body = c.req.body;

    const result = await auth.createMagicLink({
      email: body.email,
      ip: c.req.socket.remoteAddress
    });
    if (!result) c.json(null, 404);

    return c.json(result, 200);
  });

  server.post('/verify', async (c: any) => {
    const body = c.req.body;
    const authHeader = c.req.headers.authorization || '';
    const token = authHeader.split(' ')[1];

    const result = await auth.verifyToken({
      email: body.email,
      token: token
    });
    if (!result) return c.json(null, 404);

    return c.json(result, 200);
  });

  server.post('/refresh', async (c: any) => {
    const body = c.req.body;

    const token = body.refreshToken;

    const result = await auth.refreshAccessToken(token);

    return c.json(result, 200);
  });

  server.get('/sessions', async (c: any) => {
    const authHeader = c.req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer '))
      return c.json(null, 401);

    const body = c.req.body;
    const token = authHeader.split(' ')[1];
    const payload = auth.verify(token);
    const user = { email: payload.sub };

    const result = await auth.getSessions({ body, user });

    return c.json(result, 200);
  });

  server.delete('/sessions', async (c: any) => {
    const authHeader = c.req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer '))
      return c.json(null, 401);

    const body = c.req.body;
    const token = authHeader.split(' ')[1];
    const payload = auth.verify(token);
    const user = { email: payload.sub };

    const result = await auth.revokeSessions({ body, user });

    return c.json(result, 200);
  });

  server.post('/logout', async (c: any) => {
    const authHeader = c.req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer '))
      return c.json(null, 401);

    const body = c.req.body;
    const refreshToken = body.refreshToken;

    const result = await auth.logout(refreshToken);

    return c.json(result, 200);
  });

  server.start();

  return server;
}
