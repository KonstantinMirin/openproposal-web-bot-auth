// ESLint for cfbot (make lint). One rule is gated: complexity 10, the same limit
// as the Python code's mccabe max-complexity.
export default [
  {
    files: ['server.mjs'],
    languageOptions: { ecmaVersion: 'latest', sourceType: 'module' },
    linterOptions: { reportUnusedDisableDirectives: 'error' },
    rules: {
      complexity: ['error', 10],
    },
  },
];
