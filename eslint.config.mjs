// ESLint for the JavaScript in this repository (make lint): cfbot's server, the
// explainer site's renderer, and the node test that renders the runner's report.
// The limits are the Python code's: complexity 10 (mccabe max-complexity), and
// short functions.
const limits = {
  complexity: ['error', 10],
  'max-statements': ['error', 20],
  'max-lines-per-function': ['error', 40],
};

export default [
  { ignores: ['cfbot/node_modules/**'] },
  {
    files: ['cfbot/**/*.mjs', 'tests/**/*.mjs'],
    languageOptions: { ecmaVersion: 'latest', sourceType: 'module' },
    linterOptions: { reportUnusedDisableDirectives: 'error' },
    rules: limits,
  },
  {
    // A classic script: its one top-level function is the IIFE that scopes it, so the
    // statement limit holds each function inside it, not the IIFE itself.
    files: ['site/**/*.js'],
    languageOptions: { ecmaVersion: 'latest', sourceType: 'script' },
    linterOptions: { reportUnusedDisableDirectives: 'error' },
    rules: { ...limits, 'max-statements': ['error', 20, { ignoreTopLevelFunctions: true }] },
  },
];
