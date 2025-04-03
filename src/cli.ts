#!/usr/bin/env node

import { startServerWithMikroProviders } from './Server.js';

async function main() {
  const args = process.argv;

  const isRunFromCommandLine = args[1]?.includes('node_modules/.bin/mikroauth');
  const force = (process.argv[2] || '') === '--forceAuth';

  if (isRunFromCommandLine || force) {
    console.log('🔐 Welcome to MikroAuth! ✨');

    try {
      await startServerWithMikroProviders();
    } catch (error: any) {
      console.error(error);
    }
  }
}

main();
