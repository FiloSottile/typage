/** @type {import('eslint').ESLint.ConfigData} */
module.exports = {
    ignorePatterns: ['.eslintrc.cjs', 'dist/', 'tests/examples/'],
    env: {
        'shared-node-browser': true,
    },
    extends: [
        'eslint:recommended',
        'plugin:@typescript-eslint/strict-type-checked',
        'plugin:@typescript-eslint/stylistic-type-checked',
    ],
    plugins: ['@typescript-eslint', '@stylistic'],
    parser: '@typescript-eslint/parser',
    parserOptions: {
        project: true,
        tsconfigRootDir: __dirname,
    },
    root: true,
    rules: {
        '@stylistic/semi': ["error", "never"],
        '@stylistic/quotes': ["error", "double"],

        'eqeqeq': "error",
        'no-var': "error",
        'prefer-const': "error",

        'no-constant-binary-expression': "error",
        'no-self-compare': "error",
    },
};
