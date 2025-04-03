import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: ['src/index.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: false,
    clean: true,
    treeshake: true,
    minify: true,
    outDir: 'lib'
  },
  {
    entry: ['src/cli.ts'],
    format: ['esm', 'cjs'],
    platform: 'node',
    treeshake: true,
    minify: true,
    clean: false,
    outDir: 'lib'
  }
]);
