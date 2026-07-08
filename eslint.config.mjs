// Flat ESLint config. Scope: correctness lint only — formatting belongs to
// Prettier (npm run format), and type-level strictness to tsc. Rules are
// kept close to the typescript-eslint recommended baseline so contributor
// friction stays low; deviations below carry their reason.
import eslint from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**'] },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  // Plain-JS node scripts (CI guards etc): give them the node globals that
  // the TS files get from @types/node.
  { files: ['**/*.mjs'], languageOptions: { globals: globals.node } },
  {
    rules: {
      // `import qrcode = require('qrcode-generator')` in src/qr/encode.ts is
      // the correct TS syntax for that package's CJS-style export shape.
      '@typescript-eslint/no-require-imports': 'off',
      // Intentionally-unused params are prefixed with _ (e.g. _params in
      // method handlers that ignore their input).
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
);
