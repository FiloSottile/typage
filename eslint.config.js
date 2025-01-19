import eslint from "@eslint/js"
import tseslint from "typescript-eslint"
import stylistic from "@stylistic/eslint-plugin"
import tsdoc from "eslint-plugin-tsdoc"

export default tseslint.config(
    // Global ignores for generated files.
    { ignores: ["dist/", "tests/examples/age.js"] },

    eslint.configs.recommended,
    tseslint.configs.recommendedTypeChecked,
    tseslint.configs.stylisticTypeChecked,

    {
        languageOptions: {
            parserOptions: {
                projectService: {
                    // Allow slow "default project" for .js config files in the root.
                    allowDefaultProject: ["*.js"]
                },
                tsconfigRootDir: import.meta.dirname,
            }
        },
        plugins: {
            "@stylistic": stylistic,
            "tsdoc": tsdoc
        },
        rules: {
            "@stylistic/semi": ["error", "never"],
            "@stylistic/quotes": ["error", "double", { "allowTemplateLiterals": true /*"avoidEscape"*/ }],
            "@stylistic/brace-style": ["error", "1tbs", { "allowSingleLine": true }],
            "@stylistic/indent": ["error", 4],
            "curly": ["error", "multi-line"],

            "eqeqeq": "error",
            "no-var": "error",
            "prefer-const": "error",
            "no-constant-binary-expression": "error",
            "no-self-compare": "error",

            "tsdoc/syntax": "error"
        }
    },

    // tsconfig.json (used by projectService) does not include .js files by default.
    // Disable typed linting for the only .js files in the project, the examples.
    {
        files: ["tests/examples/*.js"],
        extends: [tseslint.configs.disableTypeChecked],
        rules: {
            "no-undef": "off",
        }
    },
)
