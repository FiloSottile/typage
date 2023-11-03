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
    plugins: ['@typescript-eslint'],
    parser: '@typescript-eslint/parser',
    parserOptions: {
        project: true,
        tsconfigRootDir: __dirname,
    },
    root: true,
    rules: {
        semi: ["error", "never"],
        eqeqeq: "error",
    },
};
