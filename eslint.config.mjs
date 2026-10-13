// Lint + static security for the TypeScript code (API, console). Python is covered by ruff + bandit (see README → Calidad y seguridad).
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import security from 'eslint-plugin-security';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';

export default tseslint.config(
  { ignores: ['**/dist/**', '**/node_modules/**', '**/coverage/**', 'apps/web/shots/**', 'apps/web/test-results/**', 'infra/mesh/generated/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  security.configs.recommended,
  {
    languageOptions: { globals: { ...globals.node } },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',                 // adapters/tests deal with untyped SDK/emulator payloads
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' }],
      'no-eval': 'error', 'no-implied-eval': 'error', 'no-new-func': 'error',
      'security/detect-object-injection': 'off',                    // too noisy for typed Record<> lookups; keys come from enums/allowlists
      'security/detect-non-literal-fs-filename': 'warn',            // FsObjectStorage / Terraform workdirs: path-checked, kept as a visible warning
    },
  },
  { files: ['apps/web/**/*.{ts,tsx}'], languageOptions: { globals: { ...globals.browser } }, plugins: { 'react-hooks': reactHooks }, rules: { ...reactHooks.configs.recommended.rules } },
  { files: ['**/test/**', '**/*.test.*', '**/e2e/**', '**/scripts/**'], rules: { 'security/detect-non-literal-regexp': 'off', 'security/detect-unsafe-regex': 'off' } },
);
